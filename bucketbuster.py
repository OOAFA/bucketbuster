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

USER_AGENT = "BucketBuster/1.2 (Authorized Research Only)"
DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 12
DEFAULT_DELAY = 0.12


@dataclass
class Finding:
    provider: str
    bucket: str
    url: str
    status: str
    is_listable: bool
    matched_files: List[str] = field(default_factory=list)
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


def parse_match_filters(
    ext_arg: str,
    name_arg: str,
    regex_args: Optional[List[str]],
) -> Tuple[Optional[Set[str]], List[str], List["re.Pattern[str]"]]:
    """
    Parse --match-ext, --match-name and --match-regex into normalized forms.
    Extensions are lowercased and ensured to start with '.'.
    Name patterns are lowercased substrings; '*' is treated as a wildcard
    (converted to a simple contains-all-parts match).
    Regexes are compiled case-insensitively; raises re.error if invalid.
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

    regexes: List["re.Pattern[str]"] = []
    for pattern in regex_args or []:
        if pattern.strip():
            regexes.append(re.compile(pattern, re.IGNORECASE))

    return exts, patterns, regexes


def object_matches(
    key: str,
    exts: Optional[Set[str]],
    patterns: List[str],
    regexes: List["re.Pattern[str]"],
    match_cert: bool,
) -> bool:
    """
    Decide whether an object key matches the configured filters.

    OR-logic across whichever filter kinds are supplied (extension, wildcard
    name/path pattern, regex, legacy cert-keyword detection). With no
    filters at all, everything matches.
    """
    if key == "(content detection)":
        return False

    base = key.lower().split("?")[0]
    name_only = base.rsplit("/", 1)[-1]

    has_ext_filter = exts is not None
    has_name_filter = bool(patterns)
    has_regex_filter = bool(regexes)

    if not (has_ext_filter or has_name_filter or has_regex_filter or match_cert):
        return True

    if has_ext_filter and any(base.endswith(e) or name_only.endswith(e) for e in exts):  # type: ignore[arg-type]
        return True

    if has_name_filter:
        for pat in patterns:
            if "*" in pat:
                # simple glob: all non-empty segments must appear in order, matches folders too
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
                    return True
            elif pat in base:
                return True

    if has_regex_filter and any(rx.search(key) for rx in regexes):
        return True

    if match_cert and is_cert_related(key):
        return True

    return False


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
        print(f"      [skip] private-key file blocked (use --allow-private-keys): {object_key}")
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
                        print(f"      [skip] too large ({cl} bytes): {object_key}")
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
                        print(f"      [skip] exceeded size limit while downloading: {object_key}")
                        return None
                    out.write(chunk)

            if written == 0:
                local_path.unlink(missing_ok=True)
                return None

            return str(local_path)
    except (requests.RequestException, OSError, LocationParseError, ValueError) as exc:
        print(f"      [!] download failed for {object_key}: {exc}")
        return None


def check_single_url(
    session: requests.Session,
    provider: str,
    bucket: str,
    url: str,
    do_dns: bool,
    match_filters: Tuple[Optional[Set[str]], List[str], List["re.Pattern[str]"], bool],
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

        exts, patterns, regexes, match_cert = match_filters
        is_listable = False
        matched_files: List[str] = []
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
                matched_files = [
                    f for f in all_files
                    if object_matches(f, exts, patterns, regexes, match_cert)
                ]
                notes = f"Public listing ({len(all_files)} objects visible)"
            elif (exts or match_cert) and any(
                ext in content.lower() for ext in (exts or CERT_EXTENSIONS)
            ):
                notes = "Possible matching file content in body"
                matched_files = ["(content detection)"]
            else:
                notes = "HTTP 200 – no listing detected"
        elif resp.status_code in (401, 403):
            notes = "Exists but access denied"
        elif resp.status_code == 404:
            return None
        else:
            notes = f"HTTP {resp.status_code}"

        if resp.status_code == 200 or (notes and "denied" in notes.lower()):
            return Finding(
                provider=provider,
                bucket=bucket,
                url=url,
                status=str(resp.status_code),
                is_listable=is_listable,
                matched_files=matched_files,
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
    match_filters: Tuple[Optional[Set[str]], List[str], List["re.Pattern[str]"], bool],
) -> List[Finding]:
    """Check one bucket name across selected providers."""
    clean = sanitize_bucket_name(bucket)
    if not clean:
        return []

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    results: List[Finding] = []
    for provider in providers:
        templates = PROVIDERS.get(provider, [])
        for tmpl in templates:
            url = tmpl.format(bucket=clean)
            # Extra safety: refuse to even attempt a malformed URL
            if ".." in url:
                continue
            finding = check_single_url(session, provider, clean, url, do_dns, match_filters)
            if finding:
                results.append(finding)
                # Once we find a listable or interesting result for a provider,
                # stop probing other templates for the same provider
                if finding.is_listable or finding.matched_files:
                    break
    return results


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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Object Storage Certificate Exposure Scanner (Authorized Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -w buckets.txt --providers yandex,vk
  %(prog)s -w buckets.txt --providers china
  %(prog)s -w buckets.txt --providers aliyun,tencent
  %(prog)s -w buckets.txt --dns --providers all -o findings.json --csv findings.csv
  %(prog)s -w buckets.txt --match-ext .pfx,.p12,.cer
  %(prog)s -w buckets.txt --match-name cryptopro,*keystore*,эцп
  %(prog)s -w buckets.txt --match-regex '.*backup.*\.sql$' --match-regex 'config/.*\.ya?ml$'
  %(prog)s -w buckets.txt --download --download-dir ./out
  %(prog)s -w buckets.txt --download --match-ext .pfx,.p12,.cer
  %(prog)s -w buckets.txt --download --allow-private-keys
        """,
    )
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist of potential bucket names")
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
        "--download",
        action="store_true",
        help="Download publicly accessible objects from listable buckets",
    )
    parser.add_argument(
        "--download-all",
        action="store_true",
        help="With --download, try every object in the listing (ignores --match-ext / --match-name / --match-regex)",
    )
    parser.add_argument(
        "--match-ext",
        default="",
        help="Comma-separated extensions to match, e.g. '.pfx,.p12,.cer,.crt,.zip' "
             "(applies to both scan reporting and --download; default: match everything)",
    )
    parser.add_argument(
        "--match-name",
        default="",
        help="Comma-separated name/path substrings or patterns (case-insensitive). "
             "Supports simple wildcards and matches folders too: *cert*, cryptopro, backups/*.sql",
    )
    parser.add_argument(
        "--match-regex",
        action="append",
        default=None,
        help="Regex matched against the full object key/path (case-insensitive). "
             "May be passed multiple times; matches are OR'd together.",
    )
    parser.add_argument(
        "--match-cert",
        action="store_true",
        help="Also match using the legacy built-in certificate-related extensions/keywords",
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
    args = parser.parse_args()

    # Update module-level delay used by check_single_url / download
    this = sys.modules[__name__]
    this.DEFAULT_DELAY = args.delay

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

    try:
        match_exts, match_patterns, match_regexes = parse_match_filters(
            args.match_ext, args.match_name, args.match_regex
        )
    except re.error as exc:
        print(f"[!] Invalid --match-regex pattern: {exc}")
        sys.exit(1)
    match_filters = (match_exts, match_patterns, match_regexes, args.match_cert)

    print("=" * 72)
    print("  Cloud Object Storage – Certificate Exposure Scanner")
    print("  AUTHORIZED SECURITY RESEARCH / OWN ASSETS ONLY")
    print("=" * 72)
    print()

    if args.download:
        print("[!] DOWNLOAD MODE ENABLED")
        print("    Only publicly reachable objects (HTTP 200) will be fetched.")
        print("    Private-key files are blocked unless --allow-private-keys is set.")
        if args.allow_private_keys:
            print("    [!] --allow-private-keys is ON — .pfx/.p12/.key/.pem may be saved.")
        if args.download_all:
            print("    Filter : ALL objects in public listings")
        elif match_exts or match_patterns or match_regexes or args.match_cert:
            if match_exts:
                print(f"    Extensions    : {', '.join(sorted(match_exts))}")
            if match_patterns:
                print(f"    Name patterns : {', '.join(match_patterns)}")
            if match_regexes:
                print(f"    Regex         : {', '.join(rx.pattern for rx in match_regexes)}")
            if args.match_cert:
                print("    Cert-related  : enabled (legacy keyword/extension list)")
        else:
            print("    Filter : everything reachable (default)")
        print()

    buckets = load_wordlist(args.wordlist)
    print(f"[*] Loaded {len(buckets)} candidate bucket names")
    print(f"[*] Providers : {', '.join(selected)}")
    print(f"[*] DNS check : {'enabled' if args.dns else 'disabled'}")
    print(f"[*] Threads   : {args.threads}  |  Delay: {args.delay}s")
    if args.download:
        if args.download_all:
            dl_desc = "all objects"
        elif match_exts or match_patterns or match_regexes or args.match_cert:
            parts = []
            if match_exts:
                parts.append("ext=" + ",".join(sorted(match_exts)))
            if match_patterns:
                parts.append("name=" + ",".join(match_patterns))
            if match_regexes:
                parts.append("regex=" + ",".join(rx.pattern for rx in match_regexes))
            if args.match_cert:
                parts.append("cert-related")
            dl_desc = " / ".join(parts)
        else:
            dl_desc = "everything reachable"
        print(f"[*] Download  : ON ({dl_desc})")
    else:
        print("[*] Download  : off")
    print()

    all_findings: List[Finding] = []
    csv_fieldnames = [
        "provider", "bucket", "url", "status", "is_listable",
        "matched_files", "dns_resolved", "notes", "downloaded",
    ]

    # Open report files up-front so each finding is flushed immediately
    json_fp = None
    csv_fp = None
    csv_writer = None
    if args.output:
        json_fp = open(args.output, "w", encoding="utf-8")
        json_fp.write("[\n")  # start JSON array; closed on exit
        json_fp.flush()
        print(f"[*] Streaming JSON results → {args.output}")
    if args.csv:
        csv_fp = open(args.csv, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_fp, fieldnames=csv_fieldnames)
        csv_writer.writeheader()
        csv_fp.flush()
        print(f"[*] Streaming CSV results  → {args.csv}")

    def finding_to_csv_row(finding: Finding) -> dict:
        row = asdict(finding)
        row["matched_files"] = "; ".join(finding.matched_files)
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

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_map = {
                executor.submit(check_bucket, b, selected, args.dns, match_filters): b
                for b in buckets
            }
            for fut in tqdm(
                concurrent.futures.as_completed(future_map),
                total=len(buckets),
                desc="Scanning",
            ):
                results = fut.result()
                for finding in results:
                    all_findings.append(finding)
                    write_finding_incremental(finding, first=json_first)
                    json_first = False

                    tag = "LISTABLE" if finding.is_listable else "HIT"
                    print(f"\n[{tag}] {finding.provider.upper()} | {finding.bucket}")
                    print(f"      URL    : {finding.url}")
                    print(f"      Status : {finding.status}  |  {finding.notes}")
                    if finding.dns_resolved:
                        print(f"      DNS    : resolved")
                    if finding.matched_files:
                        print(f"      Matched files:")
                        for f in finding.matched_files:
                            print(f"        • {f}")

        # ---- optional download phase (sequential, polite) ----
        if args.download and all_findings:
            print("\n" + "-" * 72)
            print("[*] Starting download phase (public objects only)")
            print("-" * 72)
            dl_root = Path(args.download_dir)
            session = requests.Session()
            session.headers.update({"User-Agent": USER_AGENT})
            total_dl = 0

            # Explicit keys from --match-name that do not contain wildcards
            explicit_keys = [
                p for p in (match_patterns or [])
                if p and "*" not in p
            ]

            for finding in all_findings:
                # Build candidate set from listing when available
                candidates: List[str] = []
                if finding.is_listable:
                    candidates = list(finding.all_files) if finding.all_files else list(finding.matched_files)
                    for mf in finding.matched_files:
                        if mf not in candidates:
                            candidates.append(mf)

                if finding.is_listable:
                    if args.download_all:
                        targets = [t for t in candidates if t]
                    else:
                        targets = [
                            t for t in candidates
                            if t and object_matches(t, match_exts, match_patterns, match_regexes, args.match_cert)
                        ]
                else:
                    targets = []

                # Always try explicit names (e.g. --match-name testfun) on
                # any discovered bucket, even if we could not parse a listing.
                for key in explicit_keys:
                    if key not in targets:
                        targets.append(key)

                if not targets:
                    continue

                print(f"\n[*] {finding.provider}/{finding.bucket} — {len(targets)} candidate object(s)")
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
                        print(f"      [+] saved: {saved}")

            print(f"\n[*] Download phase complete — {total_dl} file(s) saved under {dl_root}")

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
                print("[*] Reports updated with download paths")

    finally:
        if json_fp is not None:
            # Close the JSON array only if we still have the streamed form open
            if not reports_finalized:
                json_fp.write("\n]\n")
            json_fp.flush()
            json_fp.close()
            print(f"[+] JSON written → {args.output}")
        if csv_fp is not None:
            csv_fp.close()
            print(f"[+] CSV written  → {args.csv}")

    print("\n" + "=" * 72)
    print(f"[*] Finished. Interesting results: {len(all_findings)}")
    print("=" * 72)


if __name__ == "__main__":
    main()
