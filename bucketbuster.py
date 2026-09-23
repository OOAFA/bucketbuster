#!/usr/bin/env python3
"""
Cloud Object Storage Certificate Exposure Scanner
=================================================

Supports:
  Russia/CIS : Yandex Cloud, VK Cloud, Selectel, SberCloud
  China      : Alibaba OSS, Tencent COS, Huawei OBS, Baidu BOS

FOR AUTHORIZED SECURITY TESTING / BUG BOUNTY / OWN INFRASTRUCTURE ONLY.

This tool:
  - Optionally performs passive DNS resolution of candidate bucket hostnames
  - Probes public listability of buckets across major S3-compatible providers
  - Expands dotted names / FQDNs into subdomain bucket candidates (--recursive)
  - Recursively queues hostname-like prefixes found in public listings
  - Reports presence of certificate-related files (.pfx, .p12, CryptoPro, ЭЦП, etc.)
  - Optionally downloads publicly accessible objects (HTTP GET only, no credentials)
  - Private-key containers (.pfx / .p12 / .key) are blocked unless --allow-private-keys

Unauthorized scanning or downloading from third-party buckets may be illegal.
Use only on assets you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import random
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin, urlparse

import idna
import requests
from tqdm import tqdm
from urllib3.exceptions import LocationParseError

requests.packages.urllib3.disable_warnings()

# ASCII DNS label (after IDNA encoding): 1-63 chars, alphanumeric + hyphen
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)

# Extensions that typically contain private key material — blocked unless opted in
PRIVATE_KEY_EXTENSIONS = {".pfx", ".p12", ".key", ".p8", ".pem"}  # .pem often has keys
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024  # 25 MiB safety limit per object

# ---------------------------------------------------------------------------
# Provider endpoint templates
# {bucket} will be replaced with the candidate name
# ---------------------------------------------------------------------------

PROVIDERS: Dict[str, List[str]] = {
    # --- Russia / CIS ---
    "yandex": [
        "https://{bucket}.storage.yandexcloud.net/",
        "https://{bucket}.website.yandexcloud.net/",
        "http://{bucket}.website.yandexcloud.net/",
        "https://storage.yandexcloud.net/{bucket}/",
    ],
    "vk": [
        "https://{bucket}.hb.ru-msk.vkcloud-storage.ru/",
        "https://hb.ru-msk.vkcloud-storage.ru/{bucket}/",
        "https://{bucket}.hb.vkcloud-storage.ru/",
        "https://hb.vkcloud-storage.ru/{bucket}/",
    ],
    "selectel": [
        "https://{bucket}.s3.ru-1.storage.selcloud.ru/",
        "https://s3.ru-1.storage.selcloud.ru/{bucket}/",
        "https://{bucket}.s3.ru-3.storage.selcloud.ru/",
        "https://s3.ru-3.storage.selcloud.ru/{bucket}/",
        "https://{bucket}.selstorage.ru/",
    ],
    "sber": [
        "https://{bucket}.obs.ru-moscow-1.hc.sbercloud.ru/",
        "https://obs.ru-moscow-1.hc.sbercloud.ru/{bucket}/",
        "https://s3.cloud.ru/{bucket}/",
        "https://{bucket}.s3.cloud.ru/",
    ],
    # --- China: Alibaba Cloud OSS ---
    "aliyun": [
        "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/",
        "https://{bucket}.oss-cn-beijing.aliyuncs.com/",
        "https://{bucket}.oss-cn-shanghai.aliyuncs.com/",
        "https://{bucket}.oss-cn-shenzhen.aliyuncs.com/",
        "https://{bucket}.oss-cn-qingdao.aliyuncs.com/",
        "https://{bucket}.oss-cn-chengdu.aliyuncs.com/",
        "https://{bucket}.oss-cn-hongkong.aliyuncs.com/",
        "https://{bucket}.oss-cn-zhangjiakou.aliyuncs.com/",
        "https://{bucket}.oss-cn-guangzhou.aliyuncs.com/",
        "https://oss-cn-hangzhou.aliyuncs.com/{bucket}/",
        "https://oss-cn-beijing.aliyuncs.com/{bucket}/",
        "https://oss-cn-shanghai.aliyuncs.com/{bucket}/",
        "https://oss-cn-shenzhen.aliyuncs.com/{bucket}/",
    ],
    # --- China: Tencent Cloud COS ---
    "tencent": [
        "https://{bucket}.cos.ap-guangzhou.myqcloud.com/",
        "https://{bucket}.cos.ap-beijing.myqcloud.com/",
        "https://{bucket}.cos.ap-shanghai.myqcloud.com/",
        "https://{bucket}.cos.ap-nanjing.myqcloud.com/",
        "https://{bucket}.cos.ap-chengdu.myqcloud.com/",
        "https://{bucket}.cos.ap-chongqing.myqcloud.com/",
        "https://{bucket}.cos.ap-singapore.myqcloud.com/",
        "https://{bucket}.cos.ap-hongkong.myqcloud.com/",
        "https://cos.ap-guangzhou.myqcloud.com/{bucket}/",
        "https://cos.ap-beijing.myqcloud.com/{bucket}/",
        "https://cos.ap-shanghai.myqcloud.com/{bucket}/",
    ],
    # --- China: Huawei Cloud OBS ---
    "huawei": [
        "https://{bucket}.obs.cn-north-1.myhuaweicloud.com/",
        "https://{bucket}.obs.cn-north-4.myhuaweicloud.com/",
        "https://{bucket}.obs.cn-east-2.myhuaweicloud.com/",
        "https://{bucket}.obs.cn-east-3.myhuaweicloud.com/",
        "https://{bucket}.obs.cn-south-1.myhuaweicloud.com/",
        "https://{bucket}.obs.cn-southwest-2.myhuaweicloud.com/",
        "https://obs.cn-north-4.myhuaweicloud.com/{bucket}/",
        "https://obs.cn-east-3.myhuaweicloud.com/{bucket}/",
        "https://obs.cn-south-1.myhuaweicloud.com/{bucket}/",
    ],
    # --- China: Baidu Cloud BOS ---
    "baidu": [
        "https://{bucket}.bj.bcebos.com/",
        "https://{bucket}.bd.bcebos.com/",
        "https://{bucket}.su.bcebos.com/",
        "https://{bucket}.gz.bcebos.com/",
        "https://{bucket}.cd.bcebos.com/",
        "https://{bucket}.hkg.bcebos.com/",
        "https://bj.bcebos.com/{bucket}/",
        "https://gz.bcebos.com/{bucket}/",
        "https://s3.bj.bcebos.com/{bucket}/",
        "https://{bucket}.s3.bj.bcebos.com/",
    ],
}

# Certificate-related indicators
CERT_EXTENSIONS = {
    ".pfx", ".p12", ".cer", ".crt", ".pem", ".key",
    ".sig", ".p7b", ".p7c", ".der", ".p8",
}
CERT_KEYWORDS = [
    "cryptopro", "криптопро", "эцп", "gost", "гост",
    "certificate", "cert", "private", "signing", "code-sign",
    "keystore", "pkcs12", "pkcs#12", "digital signature",
    "подпись", "сертификат", "ключ",
]

USER_AGENT = "BucketBuster/1.3 (Authorized Research Only)"
DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 12
DEFAULT_DELAY = 0.12
VERBOSE = False
ACTIVE_UA = USER_AGENT

# Realistic desktop / mobile strings. Rotated only when the operator asks.
USER_AGENTS_COMMON = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
]

USER_AGENTS_RU = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 YaBrowser/24.7.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 YaBrowser/24.6.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 YaBrowser/24.7.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Vivaldi/6.8.3381.46",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A556E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile YaBrowser/24.7.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
]

USER_AGENTS_CN = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36 Core/1.94.225.400 QQBrowser/12.2.5547.400",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36 SE 2.X MetaSr 1.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 360Chrome/21.0.1880.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3883.400 QQBrowser/10.8.4358.400",
    "Mozilla/5.0 (Linux; Android 14; PJE110) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; ALN-AL00 Build/HONORALN-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/99.0.4844.88 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; U; Android 14; zh-CN; 2201122C Build/UKQ1.230917.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123.0.6312.80 UCBrowser/16.4.6.1354 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.49(0x18003137) NetType/WIFI Language/zh_CN",
    "Mozilla/5.0 (Linux; Android 12; HarmonyOS; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.289 Safari/537.36",
]


def pick_user_agent(args: argparse.Namespace) -> str:
    flags = [
        bool(args.useragent),
        args.random_agent,
        args.random_agent_ru,
        args.random_agent_cn,
    ]
    if sum(flags) > 1:
        raise SystemExit(
            "[!] Use only one of --useragent / --random-agent / "
            "--random-agent-ru / --random-agent-cn"
        )
    if args.useragent:
        ua = args.useragent.strip()
        if not ua:
            raise SystemExit("[!] --useragent is empty")
        return ua
    if args.random_agent_ru:
        return random.choice(USER_AGENTS_RU)
    if args.random_agent_cn:
        return random.choice(USER_AGENTS_CN)
    if args.random_agent:
        return random.choice(USER_AGENTS_COMMON)
    return USER_AGENT


def vprint(*args, **kwargs) -> None:
    if VERBOSE:
        kwargs.setdefault("flush", True)
        print(*args, **kwargs)


@dataclass
class Finding:
    provider: str
    bucket: str
    url: str
    status: str
    is_listable: bool
    cert_files: List[str] = field(default_factory=list)
    all_files: List[str] = field(default_factory=list)
    dns_resolved: bool = False
    notes: str = ""
    listing_snippet: Optional[str] = None
    downloaded: List[str] = field(default_factory=list)  # local paths


def is_cert_related(name: str) -> bool:
    lower = name.lower()
    if any(lower.endswith(ext) for ext in CERT_EXTENSIONS):
        return True
    return any(kw in lower for kw in CERT_KEYWORDS)


def is_private_key_file(name: str) -> bool:
    """True if the object name looks like a private-key container."""
    lower = name.lower().split("?")[0]
    return any(lower.endswith(ext) for ext in PRIVATE_KEY_EXTENSIONS)


def parse_download_filters(
    ext_arg: str,
    name_arg: str,
) -> Tuple[Optional[Set[str]], List[str]]:
    """
    Parse --download-ext and --download-name into normalized forms.
    Extensions are lowercased and ensured to start with '.'.
    Name patterns are lowercased substrings; '*' is treated as a wildcard
    (converted to a simple contains-all-parts match).
    """
    exts: Optional[Set[str]] = None
    if ext_arg and ext_arg.strip():
        exts = set()
        for part in ext_arg.split(","):
            part = part.strip().lower()
            if not part:
                continue
            if not part.startswith("."):
                part = "." + part
            exts.add(part)

    patterns: List[str] = []
    if name_arg and name_arg.strip():
        for part in name_arg.split(","):
            part = part.strip().lower()
            if part:
                patterns.append(part)
    return exts, patterns


def object_matches_download_filters(
    key: str,
    exts: Optional[Set[str]],
    patterns: List[str],
    default_cert_only: bool,
) -> bool:
    """
    Decide whether an object key should be downloaded.

    Priority:
      1. If extensions and/or name patterns are set → match those (OR across
         extensions, OR across patterns; if both kinds are set, object must
         match at least one extension OR at least one pattern).
      2. Else if default_cert_only → use is_cert_related().
      3. Else → accept everything.
    """
    if key == "(content detection)":
        return False

    base = key.lower().split("?")[0]
    name_only = base.rsplit("/", 1)[-1]

    has_ext_filter = exts is not None
    has_name_filter = bool(patterns)

    if has_ext_filter or has_name_filter:
        ext_ok = False
        name_ok = False
        if has_ext_filter:
            ext_ok = any(base.endswith(e) or name_only.endswith(e) for e in exts)  # type: ignore[arg-type]
        if has_name_filter:
            for pat in patterns:
                if "*" in pat:
                    # simple glob: all non-empty segments must appear in order
                    parts = [p for p in pat.split("*") if p]
                    pos = 0
                    ok = True
                    for p in parts:
                        idx = base.find(p, pos)
                        if idx < 0:
                            ok = False
                            break
                        pos = idx + len(p)
                    if ok:
                        name_ok = True
                        break
                else:
                    if pat in base:
                        name_ok = True
                        break
        if has_ext_filter and has_name_filter:
            return ext_ok or name_ok
        if has_ext_filter:
            return ext_ok
        return name_ok

    if default_cert_only:
        return is_cert_related(key)
    return True


def safe_local_name(key: str) -> str:
    """Flatten object key into a filesystem-safe relative path."""
    # Keep directory structure but neutralize path traversal
    parts = []
    for part in key.replace("\\", "/").split("/"):
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        part = re.sub(r"[^\w.\-()\[\] ]+", "_", part)
        if part:
            parts.append(part[:180])
    return "/".join(parts) if parts else "unnamed_object"


def encode_label_idna(label: str) -> Optional[str]:
    """
    Encode a single DNS label to IDNA (Punycode) ASCII form.
    Accepts Unicode (e.g. Cyrillic) or already-encoded xn-- labels.
    Returns None if the label is invalid under IDNA / DNS rules.
    """
    if not label:
        return None
    label = label.strip().strip("-")
    if not label:
        return None

    try:
        # idna.encode handles both Unicode and already-punycoded input
        # uts46=True applies UTS46 mapping (case fold, normalize, etc.)
        encoded = idna.encode(label, uts46=True).decode("ascii")
    except idna.IDNAError:
        return None

    if not encoded or len(encoded) > 63:
        return None
    if not _ASCII_LABEL_RE.match(encoded):
        return None
    return encoded


# Known storage host suffixes used to peel a bucket out of a URL/hostname
_HOST_SUFFIXES = (
    ".storage.yandexcloud.net",
    ".website.yandexcloud.net",
    ".hb.ru-msk.vkcloud-storage.ru",
    ".hb.vkcloud-storage.ru",
    ".s3.ru-1.storage.selcloud.ru",
    ".s3.ru-3.storage.selcloud.ru",
    ".selstorage.ru",
    ".obs.ru-moscow-1.hc.sbercloud.ru",
    ".s3.cloud.ru",
    ".aliyuncs.com",
    ".myqcloud.com",
    ".myhuaweicloud.com",
    ".bcebos.com",
)


def extract_bucket_from_input(raw: str) -> Optional[str]:
    """
    Accept a bare bucket name, a hostname, or a full URL and return the
    bucket name. Examples:
      my-bucket
      my-bucket.storage.yandexcloud.net
      https://my-bucket.storage.yandexcloud.net/foo.pfx
      https://storage.yandexcloud.net/my-bucket/
    """
    if not raw:
        return None
    raw = raw.strip().strip(",")
    if not raw or raw.startswith("#"):
        return None

    host = ""
    path = ""
    if "://" in raw or raw.startswith("//"):
        try:
            parsed = urlparse(raw if "://" in raw else "https:" + raw)
            host = (parsed.hostname or "").lower()
            path = parsed.path or ""
        except Exception:
            host = ""
    else:
        # hostname or name[/key]
        if "/" in raw:
            host, path = raw.split("/", 1)
            path = "/" + path
        else:
            host = raw
        host = host.lower()

    if host:
        for suffix in _HOST_SUFFIXES:
            if host.endswith(suffix):
                left = host[: -len(suffix)].strip(".")
                if left and not left.startswith("oss-") and not left.startswith("cos.") \
                        and not left.startswith("obs.") and not left.startswith("s3"):
                    return left
                # path-style: host is the endpoint, bucket is first path segment
                break
        # path-style: storage.yandexcloud.net/bucket/...
        if path:
            seg = path.lstrip("/").split("/", 1)[0]
            if seg:
                return seg
        # already a bare name (no dots that look like an endpoint)
        if host and "." not in host:
            return host
        # leftover: first label of a multi-part host
        if host and not any(host == s.lstrip(".") or host.endswith(s) for s in _HOST_SUFFIXES):
            # if it looks like just a bucket (hyphens/alnum), keep full string
            if re.match(r"^[a-z0-9][a-z0-9._-]{1,62}$", host.split(".")[0]):
                # only use first label if the rest is a known suffix we missed
                return host.split(".")[0] if any(host.endswith(s) for s in _HOST_SUFFIXES) else host

    return None


def sanitize_bucket_name(name: str) -> Optional[str]:
    """
    Normalize a candidate bucket name and convert any non-ASCII labels
    to valid IDNA (Punycode) form.

    - Accepts URLs / hostnames and extracts the bucket
    - Strips whitespace / leading-trailing dots
    - Collapses consecutive dots
    - Encodes each label with IDNA
    - Rejects names that would produce empty labels or invalid hostnames

    Returns the ASCII-safe name ready for use in hostnames, or None.
    """
    if not name:
        return None

    extracted = extract_bucket_from_input(name)
    if extracted:
        name = extracted

    name = name.strip()
    name = re.sub(r"\s+", "", name)
    name = re.sub(r"\.{2,}", ".", name)
    name = name.strip(".")

    if not name or len(name) > 253:
        return None

    labels = name.split(".")
    clean_labels: List[str] = []

    for raw_label in labels:
        encoded = encode_label_idna(raw_label)
        if encoded is None:
            return None  # any invalid label makes the whole name unusable
        clean_labels.append(encoded)

    if not clean_labels:
        return None

    result = ".".join(clean_labels)

    # Final structural checks
    if ".." in result or result.startswith(".") or result.endswith("."):
        return None
    if len(result) > 253:
        return None

    return result


def is_valid_hostname(hostname: str) -> bool:
    """
    Validate that a full hostname is structurally sound and IDNA-safe.
    Used as a last gate before HTTP/DNS operations.
    """
    if not hostname:
        return False
    if ".." in hostname or hostname.startswith(".") or hostname.endswith("."):
        return False

    try:
        # Re-encode via IDNA to confirm the whole name is legal
        idna.encode(hostname, uts46=True)
    except idna.IDNAError:
        return False

    for label in hostname.split("."):
        if not label or len(label) > 63:
            return False
        if not _ASCII_LABEL_RE.match(label):
            return False

    return len(hostname) <= 253


def extract_files_from_listing(content: str) -> List[str]:
    """Extract candidate filenames from common listing formats."""
    files: Set[str] = set()

    # S3 XML
    for m in re.finditer(r"<Key>([^<]+)</Key>", content, re.I):
        files.add(m.group(1).strip())

    # HTML Index of / hrefs
    for m in re.finditer(r'href=["\']([^"\']+)["\']', content, re.I):
        href = m.group(1)
        if href.startswith(("?", "/", "http", "mailto", "#")):
            continue
        files.add(href.split("?")[0].rstrip("/"))

    # Plain text-ish lines
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("<") and "." in line and " " not in line[:40]:
            files.add(line.split()[0])

    return sorted(f for f in files if f and not f.endswith("/"))


def dns_resolves(hostname: str) -> bool:
    """Passive DNS check – returns True if the hostname resolves to any address."""
    try:
        socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        return True
    except socket.gaierror:
        return False


def build_object_url(bucket_url: str, object_key: str) -> str:
    """
    Build a direct object URL from a bucket base URL and object key.
    Handles both virtual-hosted and path-style bases.
    """
    base = bucket_url.rstrip("/") + "/"
    # Encode each path segment but keep slashes
    encoded = "/".join(quote(seg, safe="") for seg in object_key.split("/"))
    return urljoin(base, encoded)


def download_public_object(
    session: requests.Session,
    object_url: str,
    local_path: Path,
    allow_private_keys: bool,
    object_key: str,
) -> Optional[str]:
    """
    Download a single publicly accessible object via HTTP GET.
    Returns the local path on success, None on skip/failure.
    """
    if is_private_key_file(object_key) and not allow_private_keys:
        vprint(f"      [skip] private-key file blocked (use --allow-private-keys): {object_key}")
        return None

    try:
        time.sleep(DEFAULT_DELAY)
        with session.get(
            object_url,
            timeout=DEFAULT_TIMEOUT + 10,
            allow_redirects=True,
            verify=True,
            stream=True,
        ) as resp:
            if resp.status_code != 200:
                return None

            # Size guard
            cl = resp.headers.get("Content-Length")
            if cl is not None:
                try:
                    if int(cl) > MAX_DOWNLOAD_BYTES:
                        vprint(f"      [skip] too large ({cl} bytes): {object_key}")
                        return None
                except ValueError:
                    pass

            local_path.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with open(local_path, "wb") as out:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > MAX_DOWNLOAD_BYTES:
                        out.close()
                        local_path.unlink(missing_ok=True)
                        vprint(f"      [skip] exceeded size limit while downloading: {object_key}")
                        return None
                    out.write(chunk)

            if written == 0:
                local_path.unlink(missing_ok=True)
                return None

            return str(local_path)
    except (requests.RequestException, OSError, LocationParseError, ValueError) as exc:
        vprint(f"      [!] download failed for {object_key}: {exc}")
        return None


def check_single_url(
    session: requests.Session,
    provider: str,
    bucket: str,
    url: str,
    do_dns: bool,
) -> Optional[Finding]:
    """Probe one concrete URL. Silently skips invalid hostnames."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return None

    if not hostname or not is_valid_hostname(hostname):
        return None

    dns_ok = False
    if do_dns:
        dns_ok = dns_resolves(hostname)
        if not dns_ok:
            return None

    try:
        time.sleep(DEFAULT_DELAY)
        resp = session.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
        content = resp.text[:200000]

        is_listable = False
        cert_files: List[str] = []
        all_files: List[str] = []
        notes = ""

        listing_markers = (
            "ListBucketResult", "ListBucket", "Index of",
            "<Key>", "<key>", "<Contents>", "CommonPrefixes",
        )
        if resp.status_code == 200:
            if any(marker in content for marker in listing_markers):
                is_listable = True
                all_files = extract_files_from_listing(content)
                cert_files = [f for f in all_files if is_cert_related(f)]
                notes = f"Public listing ({len(all_files)} objects visible)"
            elif any(ext in content.lower() for ext in CERT_EXTENSIONS):
                notes = "Possible certificate content in body"
                cert_files = ["(content detection)"]
            else:
                notes = "HTTP 200 – no listing detected"
        elif resp.status_code in (401, 403):
            notes = "Exists but access denied"
        elif resp.status_code == 404:
            return None
        else:
            notes = f"HTTP {resp.status_code}"

        if is_listable or cert_files or resp.status_code == 200 or (notes and "denied" in notes.lower()):
            return Finding(
                provider=provider,
                bucket=bucket,
                url=url,
                status=str(resp.status_code),
                is_listable=is_listable,
                cert_files=cert_files,
                all_files=all_files,
                dns_resolved=dns_ok if do_dns else False,
                notes=notes,
                listing_snippet=content[:500] if is_listable else None,
            )
    except (requests.RequestException, LocationParseError, ValueError):
        # LocationParseError = empty/invalid DNS label (the original crash)
        pass
    return None


def check_bucket(
    bucket: str,
    providers: List[str],
    do_dns: bool,
) -> List[Finding]:
    """Check one bucket name across selected providers."""
    clean = sanitize_bucket_name(bucket)
    if not clean:
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": ACTIVE_UA})

    results: List[Finding] = []
    for provider in providers:
        templates = PROVIDERS.get(provider, [])
        for tmpl in templates:
            url = tmpl.format(bucket=clean)
            # Extra safety: refuse to even attempt a malformed URL
            if ".." in url:
                continue
            finding = check_single_url(session, provider, clean, url, do_dns)
            if finding:
                results.append(finding)
                # Once we find a listable or interesting result for a provider,
                # stop probing other templates for the same provider
                if finding.is_listable or finding.cert_files:
                    break
    return results


def load_prefix_list(spec: str) -> List[str]:
    """
    --sub-prefixes accepts either a comma-separated string or a file path
    (one label per line, # comments ok). Never treat a missing *.txt path
    as a literal prefix.
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    if spec.lower() in {"default", "auto"}:
        return list(DEFAULT_SUB_PREFIXES)

    path = Path(spec)
    raw_items: List[str] = []
    if path.is_file():
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                raw_items.extend(p.strip() for p in line.split(",") if p.strip())
    else:
        looks_like_file = bool(re.search(r"\.(txt|lst|wl|prefixes)$", spec, re.I))
        if looks_like_file:
            raise SystemExit(
                f"[!] --sub-prefixes file not found: {spec}\n"
                f"    Pass a real file or a comma list (www,mail,dev)."
            )
        raw_items = [p.strip() for p in spec.split(",") if p.strip()]

    out: List[str] = []
    seen: Set[str] = set()
    for item in raw_items:
        item = item.lower().strip(".")
        item = re.split(r"[./\\s]+", item)[0]
        if not item or item in seen:
            continue
        if re.search(r"\.(txt|lst|wl|prefixes)$", item, re.I):
            continue
        seen.add(item)
        out.append(item)
    return out


def load_wordlist(path: str) -> List[str]:
    """Load and sanitize bucket candidates. Drops empty/invalid names."""
    seen: Set[str] = set()
    result: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            clean = sanitize_bucket_name(raw)
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
    return result


# Common left-hand labels used as bucket prefixes on RU/CN object stores
DEFAULT_SUB_PREFIXES = (
    "www", "mail", "vpn", "dev", "test", "stage", "staging", "prod",
    "backup", "bak", "old", "files", "static", "assets", "media", "cdn",
    "img", "upload", "uploads", "data", "logs", "log", "s3", "oss",
    "bucket", "storage", "public", "private", "internal", "intern",
    "corp", "office", "1c", "bitrix", "gcs", "update", "docs", "hr",
)

_SKIP_LABELS = {
    "www", "com", "net", "org", "ru", "su", "рф", "xn--p1ai",
    "cn", "comcn", "hk", "sg", "io", "aero", "info", "biz",
    "local", "internal", "lan", "corp",
}


def _bucket_ok(name: str) -> Optional[str]:
    clean = sanitize_bucket_name(name)
    if not clean:
        return None
    # Virtual-host style names are usually 3–63 chars
    if len(clean) < 3 or len(clean) > 63:
        return None
    return clean


def subdomain_bucket_variants(name: str, prefixes: List[str]) -> List[str]:
    """
    Turn one token or FQDN into bucket-name candidates.

    superdrones.aero          → superdrones, superdrones-aero, superdronesaero
    dev.mail.superdrones.aero → each suffix/prefix join, hyphen and dotted forms
    """
    raw = (name or "").strip().lower().rstrip(".")
    if not raw:
        return []

    extracted = extract_bucket_from_input(raw) or raw
    extracted = extracted.strip(".")
    labels = [lbl for lbl in re.split(r"[.\s/]+", extracted) if lbl]
    if not labels:
        return []

    variants: List[str] = []
    seen: Set[str] = set()

    def add(candidate: str) -> None:
        clean = _bucket_ok(candidate)
        if clean and clean not in seen:
            seen.add(clean)
            variants.append(clean)

    add(extracted)
    add("-".join(labels))
    add("".join(labels))

    n = len(labels)
    for i in range(n):
        for j in range(i + 1, n + 1):
            chunk = labels[i:j]
            if not chunk:
                continue
            if all(x in _SKIP_LABELS for x in chunk):
                continue
            add(".".join(chunk))
            add("-".join(chunk))
            if j - i <= 3:
                add("".join(chunk))

    cores: List[str] = []
    for lbl in labels:
        if lbl not in _SKIP_LABELS:
            add(lbl)
            cores.append(lbl)
    if n >= 2:
        cores.append("-".join(labels[:-1] if labels[-1] in _SKIP_LABELS else labels))
        cores.append("-".join(x for x in labels if x not in _SKIP_LABELS) or labels[0])

    # Prefixes only on short company-like bases, not every suffix combination
    prefix_bases = []
    for c in cores:
        clean = _bucket_ok(c)
        if clean and clean not in prefix_bases:
            prefix_bases.append(clean)
    for prefix in prefixes:
        prefix = prefix.strip().lower()
        if not prefix:
            continue
        for base in prefix_bases:
            if base.startswith(prefix + "-") or base == prefix:
                continue
            add(f"{prefix}-{base}")
            add(f"{prefix}.{base}")
    return variants


def expand_subdomain_buckets(
    seeds: List[str],
    prefixes: List[str],
    extra_subdomains: Optional[List[str]] = None,
) -> List[str]:
    """Expand a seed wordlist (and optional FQDN list) into subdomain buckets."""
    seen: Set[str] = set()
    out: List[str] = []
    items = list(seeds) + list(extra_subdomains or [])
    total = len(items)
    apply_prefixes = bool(prefixes)

    def absorb(token: str) -> None:
        # Plain already-bucket names: keep as-is unless prefixes were requested
        if "." not in token and not apply_prefixes:
            if token not in seen:
                seen.add(token)
                out.append(token)
            return
        for cand in subdomain_bucket_variants(token, prefixes):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)

    for i, token in enumerate(items, 1):
        absorb(token)
        if VERBOSE and total >= 5000 and i % 25000 == 0:
            print(f"[*] Expand {i}/{total} → {len(out)} names", flush=True)
    return out


def names_from_listing(finding: Finding) -> List[str]:
    """
    Pull hostname-like prefixes out of a public listing so they can be
    tried as *new* bucket names (one recursion hop).
    """
    keys = list(finding.all_files or []) + list(finding.cert_files or [])
    found: List[str] = []
    seen: Set[str] = set()
    parent = finding.bucket
    for key in keys:
        if not key:
            continue
        first = key.strip("/").split("/", 1)[0]
        if not first or first in seen:
            continue
        seen.add(first)
        if "." in first or re.match(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", first, re.I):
            found.append(first)
            found.append(f"{parent}-{first}")
            found.append(f"{first}-{parent}")
    return found


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Object Storage Certificate Exposure Scanner (Authorized Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Build -w with utfcewl, not from a raw 10k crawl:

  utfcewl.py https://target --translit --buckets -o words.txt
  utfcewl.py --buckets-from words.txt --buckets-extra company,product -o buckets.txt

--recursive expands FQDNs / listing prefixes. It does not turn
«супер дроны» into superdrony — that is utfcewl --buckets.

Examples:
  %(prog)s -w buckets.txt --providers yandex,vk
  %(prog)s -w buckets.txt --providers china
  %(prog)s -w buckets.txt --providers aliyun,tencent
  %(prog)s -w buckets.txt --dns --providers all -o findings.json --csv findings.csv
  %(prog)s -w buckets.txt --download --download-dir ./out
  %(prog)s -w buckets.txt --download --download-ext .pfx,.p12,.cer
  %(prog)s -w buckets.txt --download --download-name cryptopro,*keystore*,эцп
  %(prog)s -w buckets.txt --download --allow-private-keys
  %(prog)s -w company.txt --recursive --providers yandex,vk
  %(prog)s -w company.txt --recursive --subdomains ct-names.txt --max-new 150
  %(prog)s -w company.txt --recursive --sub-prefixes prefixes.txt
  %(prog)s -w company.txt --recursive -v
        """,
    )
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist of potential bucket names")
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print HITs, banners, progress, and download chatter. "
             "Default prints only LISTABLE buckets.",
    )
    parser.add_argument(
        "--providers",
        default="yandex,vk",
        help="Comma-separated: yandex,vk,selectel,sber,aliyun,tencent,huawei,baidu "
             "or 'all' / 'china' / 'russia' (default: yandex,vk)",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Enable passive DNS pre-check (skip hostnames that do not resolve)",
    )
    parser.add_argument("-o", "--output", help="Write JSON report")
    parser.add_argument("--csv", help="Write CSV report")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--delay", type=float, default=0.12,
                        help="Delay between HTTP requests (seconds)")
    parser.add_argument(
        "--useragent",
        default="",
        help="Exact User-Agent string for every request.",
    )
    parser.add_argument(
        "--random-agent",
        action="store_true",
        help="Pick one common desktop/mobile User-Agent for this run.",
    )
    parser.add_argument(
        "--random-agent-ru",
        action="store_true",
        help="Pick one RU-typical User-Agent (Yandex Browser, Ya-Android, Firefox ESR).",
    )
    parser.add_argument(
        "--random-agent-cn",
        action="store_true",
        help="Pick one CN-typical User-Agent (QQ, UC, 360, Sogou, WeChat, Harmony).",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download publicly accessible objects from listable buckets",
    )
    parser.add_argument(
        "--download-all",
        action="store_true",
        help="With --download, try every object in the listing (ignores --download-ext / --download-name)",
    )
    parser.add_argument(
        "--download-ext",
        default="",
        help="Comma-separated extensions to download, e.g. '.pfx,.p12,.cer,.crt,.zip' "
             "(default with --download: cert-related extensions only)",
    )
    parser.add_argument(
        "--download-name",
        default="",
        help="Comma-separated name substrings/patterns (case-insensitive). "
             "Supports simple wildcards: *cert*, cryptopro, *.keystore",
    )
    parser.add_argument(
        "--download-dir",
        default="./downloads",
        help="Directory for downloaded files (default: ./downloads)",
    )
    parser.add_argument(
        "--allow-private-keys",
        action="store_true",
        help="Allow download of private-key containers (.pfx, .p12, .key, .pem). "
             "OFF by default. Only use on assets you own or are authorized to test.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Expand dotted names/FQDNs into subdomain bucket candidates and "
             "queue hostname-like prefixes from listable buckets.",
    )
    parser.add_argument(
        "--subdomains",
        default="",
        help="Optional extra file of FQDNs / CT names to expand when --recursive "
             "(one host per line).",
    )
    parser.add_argument(
        "--sub-prefixes",
        default="",
        help="Left-hand labels glued onto company bases. Off unless set. "
             "Comma list (www,mail,dev), a text file, or 'default' for the "
             "built-in RU/CN sticker list. Not a bucket wordlist — that is -w.",
    )
    parser.add_argument(
        "--max-new",
        type=int,
        default=200,
        help="Cap on extra names queued from listings when --recursive (default: 200).",
    )
    args = parser.parse_args()

    # Update module-level delay used by check_single_url / download
    this = sys.modules[__name__]
    this.DEFAULT_DELAY = args.delay
    this.VERBOSE = args.verbose
    this.ACTIVE_UA = pick_user_agent(args)
    vprint(f"[*] User-Agent : {this.ACTIVE_UA}")

    prov_arg = args.providers.lower().strip()
    if prov_arg == "all":
        selected = list(PROVIDERS.keys())
    elif prov_arg == "russia":
        selected = ["yandex", "vk", "selectel", "sber"]
    elif prov_arg == "china":
        selected = ["aliyun", "tencent", "huawei", "baidu"]
    else:
        selected = [p.strip().lower() for p in args.providers.split(",")]
        unknown = [p for p in selected if p not in PROVIDERS]
        if unknown:
            print(f"[!] Unknown providers: {unknown}")
            print(f"    Available: {', '.join(PROVIDERS.keys())}")
            print(f"    Groups:    all, russia, china")
            sys.exit(1)

    if args.download_all and not args.download:
        print("[!] --download-all requires --download")
        sys.exit(1)
    if (args.download_ext or args.download_name) and not args.download:
        print("[!] --download-ext / --download-name require --download")
        sys.exit(1)

    dl_exts, dl_patterns = parse_download_filters(args.download_ext, args.download_name)
    # When user passes custom filters, do not force cert-only default
    default_cert_only = not args.download_all and dl_exts is None and not dl_patterns

    vprint("=" * 72)
    vprint("  Cloud Object Storage – Certificate Exposure Scanner")
    vprint("  AUTHORIZED SECURITY RESEARCH / OWN ASSETS ONLY")
    vprint("=" * 72)
    vprint()

    if args.download:
        vprint("[!] DOWNLOAD MODE ENABLED")
        vprint("    Only publicly reachable objects (HTTP 200) will be fetched.")
        vprint("    Private-key files are blocked unless --allow-private-keys is set.")
        if args.allow_private_keys:
            vprint("    [!] --allow-private-keys is ON — .pfx/.p12/.key/.pem may be saved.")
        if args.download_all:
            vprint("    Filter : ALL objects in public listings")
        elif dl_exts or dl_patterns:
            if dl_exts:
                vprint(f"    Extensions : {', '.join(sorted(dl_exts))}")
            if dl_patterns:
                vprint(f"    Name patterns : {', '.join(dl_patterns)}")
        else:
            vprint("    Filter : certificate-related files only (default)")
        vprint()

    buckets = load_wordlist(args.wordlist)
    vprint(f"[*] Loaded {len(buckets)} seed name(s) from wordlist")
    prefixes = load_prefix_list(args.sub_prefixes)
    if prefixes:
        src = args.sub_prefixes if Path(args.sub_prefixes).is_file() else args.sub_prefixes
        vprint(f"[*] Sub-prefixes : {len(prefixes)} from {src}")
    else:
        vprint("[*] Sub-prefixes : off (pass --sub-prefixes default or a file to enable)")
    extra_subs: List[str] = []
    if args.subdomains:
        extra_subs = load_wordlist(args.subdomains)
        vprint(f"[*] Extra FQDNs : {len(extra_subs)} from {args.subdomains}")
    if args.recursive:
        before = len(buckets)
        if before >= 10000:
            print(
                f"[*] Expanding {before} seed(s); prefixes="
                f"{len(prefixes)}. Dotted names only unless --sub-prefixes is set.",
                flush=True,
            )
        buckets = expand_subdomain_buckets(buckets, prefixes, extra_subs)
        vprint(f"[*] Recursive subdomain expand : {before} seed(s) → {len(buckets)} bucket name(s)")
        if len(buckets) >= 10000:
            print(f"[*] Scanning {len(buckets)} names × {len(selected)} providers …", flush=True)
    elif extra_subs:
        print("[!] --subdomains ignored without --recursive")
    vprint(f"[*] Providers : {', '.join(selected)}")
    vprint(f"[*] DNS check : {'enabled' if args.dns else 'disabled'}")
    vprint(f"[*] Recursive : {'on (subdomain expand + listing hop, max-new=' + str(args.max_new) + ')' if args.recursive else 'off'}")
    vprint(f"[*] Threads   : {args.threads}  |  Delay: {args.delay}s")
    if args.download:
        if args.download_all:
            dl_desc = "all objects"
        elif dl_exts or dl_patterns:
            parts = []
            if dl_exts:
                parts.append("ext=" + ",".join(sorted(dl_exts)))
            if dl_patterns:
                parts.append("name=" + ",".join(dl_patterns))
            dl_desc = " / ".join(parts)
        else:
            dl_desc = "cert-related only"
        vprint(f"[*] Download  : ON ({dl_desc})")
    else:
        vprint("[*] Download  : off")
    vprint()

    all_findings: List[Finding] = []
    csv_fieldnames = [
        "provider", "bucket", "url", "status", "is_listable",
        "cert_files", "dns_resolved", "notes", "downloaded",
    ]

    # Open report files up-front so each finding is flushed immediately
    json_fp = None
    csv_fp = None
    csv_writer = None
    if args.output:
        json_fp = open(args.output, "w", encoding="utf-8")
        json_fp.write("[\n")  # start JSON array; closed on exit
        json_fp.flush()
        vprint(f"[*] Streaming JSON results → {args.output}")
    if args.csv:
        csv_fp = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_fp, fieldnames=csv_fieldnames)
        csv_writer.writeheader()
        csv_fp.flush()
        vprint(f"[*] Streaming CSV results  → {args.csv}")

    def finding_to_csv_row(finding: Finding) -> dict:
        row = asdict(finding)
        row["cert_files"] = "; ".join(finding.cert_files)
        row["downloaded"] = "; ".join(finding.downloaded)
        row.pop("listing_snippet", None)
        row.pop("all_files", None)
        return row

    def write_finding_incremental(finding: Finding, first: bool) -> None:
        """Append one finding to open report files and flush to disk."""
        if json_fp is not None:
            if not first:
                json_fp.write(",\n")
            json.dump(asdict(finding), json_fp, indent=2, ensure_ascii=False)
            json_fp.flush()
            try:
                os.fsync(json_fp.fileno())
            except OSError:
                pass
        if csv_writer is not None and csv_fp is not None:
            csv_writer.writerow(finding_to_csv_row(finding))
            csv_fp.flush()
            try:
                os.fsync(csv_fp.fileno())
            except OSError:
                pass

    json_first = True
    reports_finalized = False
    queued: Set[str] = set()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            work: List[str] = list(buckets)
            queued = set(work)
            discovered = 0
            idx = 0
            in_flight: Dict = {}
            inflight_cap = max(args.threads * 8, 32)

            def submit_more() -> None:
                nonlocal idx
                while idx < len(work) and len(in_flight) < inflight_cap:
                    name = work[idx]
                    idx += 1
                    fut = executor.submit(check_bucket, name, selected, args.dns)
                    in_flight[fut] = name

            submit_more()
            with tqdm(
                total=len(work),
                desc="Scanning",
                file=sys.stderr,
                mininterval=0.5,
            ) as bar:
                while in_flight or idx < len(work):
                    submit_more()
                    if not in_flight:
                        break
                    done, _ = concurrent.futures.wait(
                        list(in_flight.keys()),
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for fut in done:
                        in_flight.pop(fut, None)
                        results = fut.result()
                        bar.update(1)
                        for finding in results:
                            all_findings.append(finding)
                            write_finding_incremental(finding, first=json_first)
                            json_first = False

                            if finding.is_listable or VERBOSE:
                                tag = "LISTABLE" if finding.is_listable else "HIT"
                                print(f"\n[{tag}] {finding.provider.upper()} | {finding.bucket}", flush=True)
                                print(f"      URL    : {finding.url}", flush=True)
                                print(f"      Status : {finding.status}  |  {finding.notes}", flush=True)
                                if finding.dns_resolved and VERBOSE:
                                    print(f"      DNS    : resolved", flush=True)
                                if finding.cert_files:
                                    print(f"      Cert-related files:", flush=True)
                                    for f in finding.cert_files:
                                        print(f"        • {f}", flush=True)

                            if (
                                args.recursive
                                and finding.is_listable
                                and discovered < args.max_new
                            ):
                                extras = expand_subdomain_buckets(
                                    names_from_listing(finding),
                                    prefixes,
                                )
                                for extra in extras:
                                    if extra in queued:
                                        continue
                                    if discovered >= args.max_new:
                                        break
                                    queued.add(extra)
                                    discovered += 1
                                    work.append(extra)
                                    bar.total = len(work)
                                    bar.refresh()
                    submit_more()

        # ---- optional download phase (sequential, polite) ----
        if args.download and all_findings:
            vprint("\n" + "-" * 72)
            vprint("[*] Starting download phase (public objects only)")
            vprint("-" * 72)
            dl_root = Path(args.download_dir)
            session = requests.Session()
            session.headers.update({"User-Agent": ACTIVE_UA})
            total_dl = 0

            # Explicit keys from --download-name that do not contain wildcards
            explicit_keys = [
                p for p in (dl_patterns or [])
                if p and "*" not in p
            ]

            for finding in all_findings:
                # Build candidate set from listing when available
                candidates: List[str] = []
                if finding.is_listable:
                    candidates = list(finding.all_files) if finding.all_files else list(finding.cert_files)
                    for cf in finding.cert_files:
                        if cf not in candidates:
                            candidates.append(cf)

                if finding.is_listable:
                    targets = [
                        t for t in candidates
                        if t
                        and object_matches_download_filters(
                            t,
                            dl_exts if not args.download_all else None,
                            dl_patterns if not args.download_all else [],
                            default_cert_only=default_cert_only and not args.download_all,
                        )
                    ]
                else:
                    targets = []

                # Always try explicit names (e.g. --download-name testfun) on
                # any discovered bucket, even if we could not parse a listing.
                for key in explicit_keys:
                    if key not in targets:
                        targets.append(key)

                if not targets:
                    continue

                vprint(f"\n[*] {finding.provider}/{finding.bucket} — {len(targets)} candidate object(s)")
                bucket_dir = dl_root / finding.provider / finding.bucket

                for key in targets:
                    obj_url = build_object_url(finding.url, key)
                    local = bucket_dir / safe_local_name(key)
                    saved = download_public_object(
                        session,
                        obj_url,
                        local,
                        allow_private_keys=args.allow_private_keys,
                        object_key=key,
                    )
                    if saved:
                        finding.downloaded.append(saved)
                        total_dl += 1
                        vprint(f"      [+] saved: {saved}")

            vprint(f"\n[*] Download phase complete — {total_dl} file(s) saved under {dl_root}")

            # Rewrite reports with final downloaded[] paths (complete valid documents)
            if all_findings and (json_fp is not None or csv_fp is not None):
                if json_fp is not None:
                    json_fp.seek(0)
                    json_fp.truncate()
                    json.dump(
                        [asdict(x) for x in all_findings],
                        json_fp,
                        indent=2,
                        ensure_ascii=False,
                    )
                    json_fp.write("\n")
                    json_fp.flush()
                if csv_fp is not None and csv_writer is not None:
                    csv_fp.seek(0)
                    csv_fp.truncate()
                    csv_writer.writeheader()
                    for finding in all_findings:
                        csv_writer.writerow(finding_to_csv_row(finding))
                    csv_fp.flush()
                reports_finalized = True
                vprint("[*] Reports updated with download paths")

    finally:
        if json_fp is not None:
            # Close the JSON array only if we still have the streamed form open
            if not reports_finalized:
                json_fp.write("\n]\n")
            json_fp.flush()
            json_fp.close()
            vprint(f"[+] JSON written → {args.output}")
        if csv_fp is not None:
            csv_fp.close()
            vprint(f"[+] CSV written  → {args.csv}")

    vprint("\n" + "=" * 72)
    vprint(f"[*] Finished. Interesting results: {len(all_findings)}")
    if args.recursive:
        vprint(f"[*] Names scanned (after expand / listing hop): {len(queued) if queued else len(buckets)}")
    vprint("=" * 72)


if __name__ == "__main__":
    main()
