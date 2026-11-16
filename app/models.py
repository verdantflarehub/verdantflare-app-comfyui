"""Station model catalog client, canonical_model_lock_v1 JCS digest, and offline provisioner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import threading
import time
from typing import Any, Callable
from urllib.parse import urlencode, urljoin, urlsplit

from .protocol import Error, JSONClient, request_id, token_valid, valid_id
from .task_store import TaskError, canonical

MODEL_CATEGORY_DIRS: dict[str, str] = {
    'CKPT': 'checkpoints',
    'UNET': 'unet',
    'CLIP': 'clip',
    'VAE': 'vae',
    'LORA': 'loras',
    'CNET': 'controlnet',
    'UPSC': 'upscale_models',
    'IPAD': 'ipadapter',
}
MODEL_CATEGORIES = frozenset(MODEL_CATEGORY_DIRS)

MODEL_STATUSES = frozenset({
    'not_installed',
    'queued',
    'downloading',
    'verifying_sha256',
    'ready',
    'failed',
    'evicting',
})

LICENSE_TIER_COMMERCIAL_FREE = 'commercial_free'
LICENSE_TIER_RESEARCH_NON_COMMERCIAL = 'research_non_commercial'
LICENSE_TIER_PAID_FORBIDDEN = 'paid_forbidden'

DEFAULT_RESERVED_HEADROOM_BYTES = 200 * 1024 * 1024 * 1024  # 200 GiB
DEFAULT_MAX_AUTO_PULL_BYTES = 25 * 1024 * 1024 * 1024       # 25 GiB
MAX_CATALOG_MODEL_BYTES = 26843545600                       # 25 GiB schema ceiling
MAX_SAFETENSORS_HEADER_BYTES = 100 * 1024 * 1024            # 100 MiB
MAX_REDIRECTS = 5

DEFAULT_ALLOWED_HOSTS = frozenset({
    'huggingface.co',
    'cdn-lfs.huggingface.co',
    'cdn-lfs-us-1.huggingface.co',
    'cdn-lfs-eu-1.huggingface.co',
    'cas-bridge.xethub.hf.co',
    'civitai.com',
    'github.com',
    'objects.githubusercontent.com',
})

COMMERCIAL_FREE_LICENSES = frozenset({
    'apache-2.0',
    'mit',
    'bsd-3-clause',
    'cc-by-4.0',
    'openrail++',
})

CATALOG_CODE_RE = re.compile(r'^MDL-(CKPT|UNET|CLIP|VAE|LORA|CNET|UPSC|IPAD)-[A-Z0-9]{2,24}-[0-9]{3}\Z')
MODEL_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,80}\Z')
SHA256_RE = re.compile(r'^[a-f0-9]{64}\Z')
FILENAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,120}\.safetensors\Z')
LICENSE_RE = re.compile(r'^[A-Za-z0-9._+-]{2,64}\Z')

_DTYPE_WIDTHS: dict[str, int] = {
    'BOOL': 1,
    'U8': 1,
    'I8': 1,
    'F8_E4M3': 1,
    'F8_E5M2': 1,
    'F16': 2,
    'BF16': 2,
    'I16': 2,
    'U16': 2,
    'F32': 4,
    'I32': 4,
    'U32': 4,
    'F64': 8,
    'I64': 8,
    'U64': 8,
}

_HOST_PATH_PATTERNS = (
    re.compile(r'(?i)/data/models[^\s"\']*'),
    re.compile(r'(?i)/var/lib/station[^\s"\']*'),
    re.compile(r'(?i)[a-z]:\\[^\s"\']*'),
)


def sanitize_model_message(text: str | None) -> str | None:
    if not isinstance(text, str):
        return None
    out = text.strip()
    for pat in _HOST_PATH_PATTERNS:
        out = pat.sub('[REDACTED_PATH]', out)
    out = re.sub(r'(?i)(bearer\s+\S+|token=[^&\s]+|key=[^&\s]+)', '[REDACTED_CREDENTIAL]', out)
    return out[:256]


def relative_view_path(category: str, sha256_hex: str, filename: str) -> str:
    if category not in MODEL_CATEGORY_DIRS:
        raise Error('INVALID_PARAMETERS', 400)
    sha = sha256_hex.strip().lower()
    if not SHA256_RE.fullmatch(sha):
        raise Error('INVALID_PARAMETERS', 400)
    validate_safetensors_filename(filename)
    return f"{MODEL_CATEGORY_DIRS[category]}/{sha[:12]}__{filename}"


def validate_safetensors_filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename or '\x00' in filename:
        raise Error('INVALID_PARAMETERS', 400)
    if '/' in filename or '\\' in filename or '..' in filename or filename != os.path.basename(filename):
        raise Error('INVALID_PARAMETERS', 400)
    if not filename.endswith('.safetensors') or not FILENAME_RE.fullmatch(filename):
        raise Error('UNSAFE_MODEL_FORMAT', 400)
    return filename


def _truthy_policy_flag(value: Any) -> bool:
    if value is True:
        return True
    if type(value) is int:
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {'true', '1', 'yes', 'paid', 'required'}
    return False


def _license_tier_rank(tier: str) -> int:
    if tier == LICENSE_TIER_COMMERCIAL_FREE:
        return 0
    if tier == LICENSE_TIER_RESEARCH_NON_COMMERCIAL:
        return 1
    if tier == LICENSE_TIER_PAID_FORBIDDEN:
        return 2
    return -1


def classify_license_tier(license_spdx: str, paid_access: bool = False, source_policy: dict[str, Any] | None = None) -> str:
    if paid_access is True:
        return LICENSE_TIER_PAID_FORBIDDEN
    policy = source_policy if isinstance(source_policy, dict) else {}
    for flag_key in (
        'paidAccess', 'paid_access', 'earlyAccess', 'early_access',
        'EarlyAccess', 'requires_subscription', 'requiresSubscription',
    ):
        if _truthy_policy_flag(policy.get(flag_key)):
            return LICENSE_TIER_PAID_FORBIDDEN
    for deadline_key in ('earlyAccessDeadline', 'early_access_deadline', 'earlyAccessEndsAt'):
        raw_dl = policy.get(deadline_key)
        if raw_dl is not None and str(raw_dl).strip() != '':
            return LICENSE_TIER_PAID_FORBIDDEN
    lic = (license_spdx or '').strip().lower()
    if any(tok in lic for tok in ('paid', 'early-access', 'early_access', 'commercial-paid', 'subscription')):
        return LICENSE_TIER_PAID_FORBIDDEN
    if lic in COMMERCIAL_FREE_LICENSES:
        return LICENSE_TIER_COMMERCIAL_FREE
    return LICENSE_TIER_RESEARCH_NON_COMMERCIAL


def normalize_canonical_model_lock_items(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize and validate the exact 9-field canonical_model_lock_v1 array (§4.3.1)."""
    if not isinstance(dependencies, list):
        raise Error('INVALID_PARAMETERS', 400)
    seen_by_key: dict[tuple[str, str], str] = {}
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for raw in dependencies:
        if not isinstance(raw, dict):
            raise Error('INVALID_PARAMETERS', 400)
        catalog_code = str(raw.get('catalog_code', '')).strip()
        model_id = str(raw.get('model_id', '')).strip()
        category = str(raw.get('category', '')).strip().upper()
        filename = str(raw.get('filename', '')).strip()
        sha256_hex = str(raw.get('sha256', '')).strip().lower()
        size_bytes = raw.get('size_bytes')
        vram_mib = raw.get('vram_footprint_mib')
        license_str = str(raw.get('license', '')).strip()
        if 'paid_access' not in raw:
            raise Error('INVALID_PARAMETERS', 400)
        paid_val = raw['paid_access']
        if type(paid_val) is not bool:
            raise Error('INVALID_PARAMETERS', 400)
        if paid_val is True:
            raise Error('MODEL_PAID_ACCESS_FORBIDDEN', 403)

        if (not CATALOG_CODE_RE.fullmatch(catalog_code)
                or not MODEL_ID_RE.fullmatch(model_id)
                or category not in MODEL_CATEGORIES
                or not catalog_code.startswith(f'MDL-{category}-')
                or not SHA256_RE.fullmatch(sha256_hex)
                or type(size_bytes) is not int or not (1 <= size_bytes <= MAX_CATALOG_MODEL_BYTES)
                or type(vram_mib) is not int or not (1 <= vram_mib <= 29696)
                or not LICENSE_RE.fullmatch(license_str)):
            raise Error('INVALID_PARAMETERS', 400)
        validate_safetensors_filename(filename)
        expected_rel = relative_view_path(category, sha256_hex, filename)
        if 'relative_view_path' in raw and raw['relative_view_path'] is not None:
            if str(raw['relative_view_path']).strip() != expected_rel:
                raise Error('INVALID_PARAMETERS', 400)

        conflict_key = (category, model_id)
        if conflict_key in seen_by_key and seen_by_key[conflict_key] != sha256_hex:
            raise Error('MODEL_CATALOG_SHA256_MISMATCH', 409)
        seen_by_key[conflict_key] = sha256_hex

        deduped[(category, model_id, sha256_hex)] = {
            'catalog_code': catalog_code,
            'model_id': model_id,
            'category': category,
            'filename': filename,
            'sha256': sha256_hex,
            'size_bytes': size_bytes,
            'vram_footprint_mib': vram_mib,
            'license': license_str,
            'paid_access': False,
        }

    ordered_keys = sorted(deduped.keys())
    return [deduped[k] for k in ordered_keys]


def compute_model_dependencies_sha256(dependencies: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Return (model_dependencies_sha256, normalized_items) using JCS / RFC 8785 (§4.3.1)."""
    normalized = normalize_canonical_model_lock_items(dependencies)
    envelope = {
        'schema_version': 'canonical_model_lock_v1',
        'models': normalized,
    }
    encoded = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest(), normalized


def sanitize_public_model_item(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise Error('MODEL_CATALOG_UNAVAILABLE', 503)
    category = str(raw.get('category', '')).upper()
    sha = str(raw.get('sha256', '')).lower()
    filename = str(raw.get('filename', ''))
    rel_view = raw.get('relative_view_path')
    if not isinstance(rel_view, str) or not rel_view:
        if category in MODEL_CATEGORY_DIRS and len(sha) >= 12 and filename:
            rel_view = f"{MODEL_CATEGORY_DIRS[category]}/{sha[:12]}__{filename}"
        else:
            rel_view = ''
    status = str(raw.get('status', 'not_installed'))
    if status not in MODEL_STATUSES:
        status = 'not_installed'
    out: dict[str, Any] = {
        'model_id': str(raw.get('model_id', '')),
        'catalog_code': str(raw.get('catalog_code', '')),
        'display_name': str(raw.get('display_name', '')),
        'category': category,
        'filename': filename,
        'relative_view_path': sanitize_model_message(rel_view) or '',
        'sha256': sha,
        'size_bytes': int(raw.get('size_bytes', 0)),
        'vram_footprint_mib': int(raw.get('vram_footprint_mib', 0)),
        'license': str(raw.get('license', '')),
        'license_tier': str(raw.get('license_tier') or classify_license_tier(str(raw.get('license', '')), bool(raw.get('paid_access', False)))),
        'paid_access': bool(raw.get('paid_access', False)),
        'origin_kind': str(raw.get('origin_kind', 'catalog')),
        'approval_state': str(raw.get('approval_state', 'approved')),
        'status': status,
        'download_fence': int(raw.get('download_fence', 0)),
        'bytes_downloaded': int(raw.get('bytes_downloaded', 0)),
        'part_bytes_on_disk': int(raw.get('part_bytes_on_disk', 0)),
        'speed_bps': int(raw.get('speed_bps', 0)),
        'eta_seconds': int(raw['eta_seconds']) if type(raw.get('eta_seconds')) is int else None,
        'active_pins': int(raw.get('active_pins', 0)),
        'reserved_pins': int(raw.get('reserved_pins', 0)),
    }
    if raw.get('last_error_code'):
        out['last_error_code'] = str(raw['last_error_code'])
    if raw.get('last_error_message'):
        out['last_error_message'] = sanitize_model_message(str(raw['last_error_message']))
    return out


def classify_ip_ssrf(addr_str: str) -> tuple[bool, str]:
    """Return (allowed, reason) blocking loopback, RFC1918, CGNAT, link-local, metadata, multicast, NAT64, Teredo, 6to4, and IPv4-mapped private IPs."""
    try:
        ip = ipaddress.ip_address(addr_str)
    except ValueError:
        return False, 'malformed_ip'
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
        elif ip.teredo is not None:
            return False, 'ipv6_teredo'
        elif ip in ipaddress.ip_network('64:ff9b::/96') or ip in ipaddress.ip_network('64:ff9b:1::/48'):
            return False, 'ipv6_nat64'
        elif ip in ipaddress.ip_network('::/96'):
            return False, 'ipv4_compatible_ipv6'
        elif ip == ipaddress.ip_address('fd00:ec2::254'):
            return False, 'cloud_metadata_ipv6'

    if isinstance(ip, ipaddress.IPv4Address):
        if ip == ipaddress.ip_address('169.254.169.254'):
            return False, 'cloud_metadata_ipv4'
        if ip in ipaddress.ip_network('100.64.0.0/10'):
            return False, 'rfc6598_cgnat'
        if ip in ipaddress.ip_network('198.18.0.0/15'):
            return False, 'benchmark_network'

    if (ip.is_unspecified or ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or not ip.is_global):
        return False, 'non_public_ip'
    return True, ''


def validate_safetensors_bytes_or_file(path_or_bytes: Path | bytes, expected_size: int | None = None) -> None:
    """Strict .safetensors binary frame validator matching Go ValidateSafetensorsFile (§4.3.1)."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = bytes(path_or_bytes)
        total_size = len(raw)
        if expected_size is not None and total_size != expected_size:
            raise Error('MODEL_SHA256_MISMATCH', 422)
        if total_size <= 8:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        header_len = struct.unpack('<Q', raw[:8])[0]
        if header_len < 2 or header_len > MAX_SAFETENSORS_HEADER_BYTES or 8 + header_len > total_size:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        header_bytes = raw[8:8 + header_len]
    else:
        p = Path(path_or_bytes)
        if not p.is_file() or p.is_symlink():
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        total_size = p.stat().st_size
        if expected_size is not None and total_size != expected_size:
            raise Error('MODEL_SHA256_MISMATCH', 422)
        if total_size <= 8:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        with p.open('rb') as f:
            len_bytes = f.read(8)
            if len(len_bytes) != 8:
                raise Error('UNSAFE_MODEL_FORMAT', 400)
            header_len = struct.unpack('<Q', len_bytes)[0]
            if header_len < 2 or header_len > MAX_SAFETENSORS_HEADER_BYTES or 8 + header_len > total_size:
                raise Error('UNSAFE_MODEL_FORMAT', 400)
            header_bytes = f.read(header_len)
            if len(header_bytes) != header_len:
                raise Error('UNSAFE_MODEL_FORMAT', 400)

    if b'\x00' in header_bytes:
        raise Error('UNSAFE_MODEL_FORMAT', 400)
    try:
        header_str = header_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise Error('UNSAFE_MODEL_FORMAT', 400) from None

    stripped = header_str.lstrip(' \t\r\n')
    if not stripped.startswith('{'):
        raise Error('UNSAFE_MODEL_FORMAT', 400)

    def _no_dup_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise Error('UNSAFE_MODEL_FORMAT', 400)
            obj[k] = v
        return obj

    def _bad_constant(_val: str):
        raise Error('UNSAFE_MODEL_FORMAT', 400)

    def _reject_float(_val: str):
        raise Error('UNSAFE_MODEL_FORMAT', 400)

    try:
        parsed = json.loads(
            header_str,
            object_pairs_hook=_no_dup_pairs,
            parse_constant=_bad_constant,
            parse_float=_reject_float,
        )
    except Error:
        raise
    except Exception:
        raise Error('UNSAFE_MODEL_FORMAT', 400) from None

    if not isinstance(parsed, dict):
        raise Error('UNSAFE_MODEL_FORMAT', 400)

    spans: list[tuple[int, int]] = []
    tensor_count = 0
    for key, val in parsed.items():
        if key == '__metadata__':
            if not isinstance(val, dict) or any(not isinstance(mk, str) or not isinstance(mv, str) for mk, mv in val.items()):
                raise Error('UNSAFE_MODEL_FORMAT', 400)
            continue
        if not key or not isinstance(val, dict) or set(val.keys()) != {'dtype', 'shape', 'data_offsets'}:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        dtype = val['dtype']
        shape = val['shape']
        offsets = val['data_offsets']
        if not isinstance(dtype, str) or dtype.upper() not in _DTYPE_WIDTHS:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        width = _DTYPE_WIDTHS[dtype.upper()]
        if not isinstance(shape, list) or any(type(dim) is not int or dim < 0 for dim in shape):
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        if not isinstance(offsets, list) or len(offsets) != 2 or any(type(o) is not int or o < 0 for o in offsets):
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        begin, end = offsets[0], offsets[1]
        if end < begin:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        elem_count = 1
        for dim in shape:
            elem_count *= dim
            if elem_count > MAX_CATALOG_MODEL_BYTES:
                raise Error('UNSAFE_MODEL_FORMAT', 400)
        expected_span = elem_count * width
        if end - begin != expected_span:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        spans.append((begin, end))
        tensor_count += 1

    if tensor_count == 0:
        raise Error('UNSAFE_MODEL_FORMAT', 400)

    spans.sort(key=lambda item: (item[0], item[1]))
    cursor = 0
    for begin, end in spans:
        if begin != cursor:
            raise Error('UNSAFE_MODEL_FORMAT', 400)
        cursor = end

    if 8 + header_len + cursor != total_size:
        raise Error('UNSAFE_MODEL_FORMAT', 400)


class ModelCacheClient:
    """HTTP client talking to station-runtime :5055 /internal/v1/model-cache/*."""

    def __init__(self, origin: str, token: str, station_id: str, *, timeout: float = 15.0):
        if not token_valid(token) or not valid_id(station_id):
            raise ValueError('valid runtime credential and station_id required')
        self.client = JSONClient(origin, timeout=timeout, max_bytes=512 << 10)
        self.token = token
        self.station_id = station_id
        self._known_hashes_lock = threading.Lock()
        self._known_hashes: set[str] = set()

    def _headers(self) -> dict[str, str]:
        return {
            'Authorization': 'Bearer ' + self.token,
            'X-Station-Id': self.station_id,
        }

    def _remember_hashes(self, items: list[dict[str, Any]]) -> None:
        with self._known_hashes_lock:
            for item in items:
                sha = item.get('sha256') if isinstance(item, dict) else None
                if isinstance(sha, str) and SHA256_RE.fullmatch(sha.lower()):
                    self._known_hashes.add(sha.lower())

    def known_sha256_digests(self) -> set[str]:
        with self._known_hashes_lock:
            if self._known_hashes:
                return set(self._known_hashes)
        try:
            res = self.list_models(limit=100)
            items = res.get('items', [])
            if isinstance(items, list):
                self._remember_hashes(items)
        except Error:
            pass
        with self._known_hashes_lock:
            return set(self._known_hashes)

    def list_models(
        self,
        *,
        category: str | None = None,
        status: str | None = None,
        query: str | None = None,
        cursor: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        params: dict[str, str] = {'limit': str(limit)}
        if category:
            params['category'] = category
        if status:
            params['status'] = status
        if query:
            params['query'] = query
        if cursor:
            params['cursor'] = cursor
        raw = self.client.request(
            'GET', '/internal/v1/model-cache/models', None,
            self._headers(), query=params, passthrough_errors=True,
        )
        models_raw = raw.get('models') if isinstance(raw, dict) else None
        if not isinstance(models_raw, list):
            raise Error('MODEL_CATALOG_UNAVAILABLE', 503)
        items = [sanitize_public_model_item(m) for m in models_raw]
        self._remember_hashes(items)
        next_cursor = raw.get('next_cursor')
        return {
            'items': items,
            'next_cursor': str(next_cursor) if isinstance(next_cursor, str) and next_cursor else None,
        }

    def get_model_status(self, model_id: str) -> dict[str, Any]:
        if not MODEL_ID_RE.fullmatch(model_id):
            raise Error('INVALID_PARAMETERS', 400)
        raw = self.client.request(
            'GET', f'/internal/v1/model-cache/models/{model_id}', None,
            self._headers(), passthrough_errors=True,
        )
        raw_item = raw['model'] if isinstance(raw, dict) and isinstance(raw.get('model'), dict) else raw
        item = sanitize_public_model_item(raw_item)
        self._remember_hashes([item])
        return item

    def ensure_model(
        self,
        *,
        organization_id: str,
        project_id: str,
        principal_id: str,
        idempotency_key: str,
        model_id: str,
        target_alias: str = 'default',
        catalog_code: str | None = None,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            'organization_id': organization_id,
            'project_id': project_id,
            'principal_id': principal_id,
            'target_alias': target_alias,
            'idempotency_key': idempotency_key,
            'model_id': model_id,
        }
        if catalog_code is not None:
            payload['catalog_code'] = catalog_code
        if expected_sha256 is not None:
            payload['expected_sha256'] = expected_sha256
        raw = self.client.request(
            'POST', '/internal/v1/model-cache/models/ensure', payload,
            self._headers(), accepted_statuses=(200, 202), passthrough_errors=True,
        )
        if not isinstance(raw, dict) or not isinstance(raw.get('model'), dict):
            raise Error('MODEL_CATALOG_UNAVAILABLE', 503)
        model_view = sanitize_public_model_item(raw['model'])
        self._remember_hashes([model_view])
        out: dict[str, Any] = {
            'deduplicated': bool(raw.get('deduplicated', False)),
            'model': model_view,
        }
        if raw.get('code'):
            out['code'] = str(raw['code'])
        if raw.get('message'):
            out['message'] = sanitize_model_message(str(raw['message']))
        if isinstance(raw.get('canonical_lock'), dict):
            out['canonical_lock'] = normalize_canonical_model_lock_items([raw['canonical_lock']])[0]
        return out

    def reserve_pins(
        self,
        *,
        reservation_id: str,
        operation_id: str,
        scope_kind: str,
        owner_id: str,
        organization_id: str,
        project_id: str,
        request_sha256: str,
        sha256_list: list[str],
        ttl_seconds: int = 60,
    ) -> dict[str, Any]:
        return self.client.request(
            'POST',
            '/internal/v1/model-cache/pins/reserve',
            {
                'reservation_id': reservation_id,
                'operation_id': operation_id,
                'scope_kind': scope_kind,
                'owner_id': owner_id,
                'organization_id': organization_id,
                'project_id': project_id,
                'request_sha256': request_sha256,
                'sha256_list': sha256_list,
                'ttl_seconds': ttl_seconds,
            },
            self._headers(),
            passthrough_errors=True,
        )

    def commit_pins(self, *, reservation_id: str, owner_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {'reservation_id': reservation_id}
        if owner_id:
            payload['owner_id'] = owner_id
        return self.client.request(
            'POST', '/internal/v1/model-cache/pins/commit', payload,
            self._headers(), passthrough_errors=True,
        )

    def release_pins(self, *, reservation_id: str, reason: str = '') -> dict[str, Any]:
        return self.client.request(
            'POST',
            '/internal/v1/model-cache/pins/release',
            {'reservation_id': reservation_id, 'reason': reason},
            self._headers(),
            passthrough_errors=True,
        )


@dataclass
class _PinGroup:
    reservation_id: str
    operation_id: str
    scope_kind: str
    owner_id: str
    organization_id: str
    project_id: str
    request_sha256: str
    sha256_list: list[str]
    state: str  # 'reserved' | 'active'
    expires_at: float | None
    created_at: float = 0.0


class LocalModelProvisioner:
    """Deterministic local CAS/view & two-phase pin provisioner for offline COMFY-P-B and T3.3 tests."""

    def __init__(
        self,
        root_dir: str | Path,
        *,
        free_bytes_fn: Callable[[], int] | None = None,
        allowed_hosts: set[str] | frozenset[str] = DEFAULT_ALLOWED_HOSTS,
        dns_resolver: Callable[[str], list[str]] | None = None,
        upstream_fetcher: Callable[[str, dict[str, str]], tuple[int, dict[str, str], bytes]] | None = None,
        revoker: Callable[[str], dict[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
        reserved_headroom_bytes: int = DEFAULT_RESERVED_HEADROOM_BYTES,
        max_auto_pull_bytes: int = DEFAULT_MAX_AUTO_PULL_BYTES,
    ):
        self.root_dir = Path(root_dir)
        self.free_bytes_fn = free_bytes_fn or (lambda: 600 * 1024 * 1024 * 1024)
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.dns_resolver = dns_resolver
        self.upstream_fetcher = upstream_fetcher
        self.revoker = revoker
        self.clock = clock
        self.reserved_headroom_bytes = max(DEFAULT_RESERVED_HEADROOM_BYTES, reserved_headroom_bytes)
        self.max_auto_pull_bytes = min(DEFAULT_MAX_AUTO_PULL_BYTES, max_auto_pull_bytes)

        self._lock = threading.RLock()
        self._catalog_by_id: dict[str, dict[str, Any]] = {}
        self._blobs_by_sha: dict[str, dict[str, Any]] = {}
        self._pins_by_res: dict[str, _PinGroup] = {}
        self._revoked_tombstones: set[str] = set()
        self._idem: dict[tuple[str, str, str, str, str], tuple[str, dict[str, Any], float]] = {}
        self._ensure_layout()

    def _ensure_layout(self) -> None:
        (self.root_dir / '.staging').mkdir(parents=True, exist_ok=True)
        (self.root_dir / 'cas').mkdir(parents=True, exist_ok=True)
        for sub in MODEL_CATEGORY_DIRS.values():
            (self.root_dir / 'views' / sub).mkdir(parents=True, exist_ok=True)

    def register_catalog_entries(self, entries: list[dict[str, Any]]) -> None:
        with self._lock:
            for raw in entries:
                entry = dict(raw)
                model_id = str(entry['model_id']).strip()
                cat_code = str(entry['catalog_code']).strip()
                category = str(entry['category']).strip().upper()
                filename = str(entry['filename']).strip()
                sha = str(entry['sha256']).strip().lower()
                if (not MODEL_ID_RE.fullmatch(model_id)
                        or not CATALOG_CODE_RE.fullmatch(cat_code)
                        or category not in MODEL_CATEGORIES
                        or not SHA256_RE.fullmatch(sha)):
                    raise Error('INVALID_PARAMETERS', 400)
                paid = bool(entry.get('paid_access', False))
                source_policy = entry.get('source_policy') if isinstance(entry.get('source_policy'), dict) else {}
                raw_license = str(entry.get('license', 'openrail++'))
                inferred_tier = classify_license_tier(raw_license, paid, source_policy)
                explicit_tier = entry.get('license_tier')
                if explicit_tier is not None and str(explicit_tier).strip():
                    explicit_str = str(explicit_tier).strip()
                    if _license_tier_rank(explicit_str) < 0 or _license_tier_rank(explicit_str) < _license_tier_rank(inferred_tier):
                        raise Error('INVALID_PARAMETERS', 400)
                    tier = explicit_str
                else:
                    tier = inferred_tier
                origin_kind = str(entry.get('origin_kind', 'catalog'))
                approval_state = str(entry.get('approval_state') or ('pending_admin' if (origin_kind == 'local' or tier == LICENSE_TIER_RESEARCH_NON_COMMERCIAL) else 'approved'))
                normalized = {
                    'model_id': model_id,
                    'catalog_code': cat_code,
                    'display_name': str(entry.get('display_name', model_id)),
                    'category': category,
                    'filename': filename,
                    'sha256': sha,
                    'size_bytes': int(entry['size_bytes']),
                    'vram_footprint_mib': int(entry.get('vram_footprint_mib', 0)),
                    'license': str(entry.get('license', 'openrail++')),
                    'license_tier': tier,
                    'paid_access': paid,
                    'origin_kind': origin_kind,
                    'approval_state': approval_state,
                    'source_urls': list(entry.get('source_urls', [])),
                    'source_policy': source_policy,
                }
                self._catalog_by_id[model_id] = normalized
                self._blobs_by_sha.setdefault(sha, {
                    'sha256': sha,
                    'size_bytes': normalized['size_bytes'],
                    'status': 'not_installed',
                    'download_fence': 0,
                    'bytes_downloaded': 0,
                    'part_bytes_on_disk': 0,
                    'speed_bps': 0,
                    'eta_seconds': None,
                    'etag': '',
                    'published_views': [],
                    'last_error_code': None,
                    'last_error_message': None,
                })

    def seed_ready_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Register a catalog entry and materialize a verified local CAS/view stub as ready (offline test helper)."""
        with self._lock:
            self.register_catalog_entries([entry])
            norm = self._catalog_by_id[str(entry['model_id']).strip()]
            sha = norm['sha256']
            cas_path = self.root_dir / 'cas' / sha
            if not cas_path.exists():
                hdr_bytes = b'{"t":{"dtype":"F16","shape":[2,2],"data_offsets":[0,8]}}'
                cas_path.write_bytes(struct.pack('<Q', len(hdr_bytes)) + hdr_bytes + (b'\x00' * 8))
            blob = self._blobs_by_sha[sha]
            blob['download_fence'] += 1
            self._publish_view_locked(norm, blob['download_fence'])
            blob['status'] = 'ready'
            blob['bytes_downloaded'] = norm['size_bytes']
            blob['part_bytes_on_disk'] = 0
            blob['eta_seconds'] = 0
            blob['last_error_code'] = None
            blob['last_error_message'] = None
            return self._status_view_locked(norm)

    def known_sha256_digests(self) -> set[str]:
        with self._lock:
            return {e['sha256'] for e in self._catalog_by_id.values()}

    def _pin_counts_locked(self, sha: str) -> tuple[int, int]:
        active = 0
        reserved = 0
        for g in self._pins_by_res.values():
            if sha in g.sha256_list:
                if g.state == 'active':
                    active += 1
                elif g.state == 'reserved':
                    reserved += 1
        return active, reserved

    def _status_view_locked(self, entry: dict[str, Any]) -> dict[str, Any]:
        blob = self._blobs_by_sha[entry['sha256']]
        active, reserved = self._pin_counts_locked(entry['sha256'])
        rel = f"{MODEL_CATEGORY_DIRS[entry['category']]}/{entry['sha256'][:12]}__{entry['filename']}"
        merged = {
            **entry,
            **blob,
            'relative_view_path': rel,
            'active_pins': active,
            'reserved_pins': reserved,
        }
        if blob['status'] == 'ready' and rel not in blob.get('published_views', ()):
            merged['status'] = 'not_installed'
            merged['bytes_downloaded'] = 0
        return sanitize_public_model_item(merged)

    def list_models(
        self,
        *,
        category: str | None = None,
        status: str | None = None,
        query: str | None = None,
        cursor: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        with self._lock:
            entries = sorted(self._catalog_by_id.values(), key=lambda e: e['catalog_code'])
            items: list[dict[str, Any]] = []
            next_cursor: str | None = None
            for e in entries:
                if cursor and e['catalog_code'] <= cursor:
                    continue
                if category and e['category'] != category:
                    continue
                if query:
                    q = query.lower()
                    if q not in e['model_id'].lower() and q not in e['catalog_code'].lower() and q not in e['display_name'].lower():
                        continue
                view = self._status_view_locked(e)
                if status and view['status'] != status:
                    continue
                if len(items) == limit:
                    next_cursor = items[-1]['catalog_code']
                    break
                items.append(view)
            return {'items': items, 'next_cursor': next_cursor}

    def get_model_status(self, model_id: str) -> dict[str, Any]:
        with self._lock:
            entry = self._catalog_by_id.get(model_id)
            if entry is None:
                raise Error('MODEL_NOT_FOUND', 404)
            return self._status_view_locked(entry)

    def _validate_url_ssrf(self, raw_url: str) -> tuple[str, str]:
        from .diagnostics import sanitize_text
        audit_detail = {'url_audit': sanitize_text(str(raw_url))}
        if not isinstance(raw_url, str) or not raw_url.strip() or any(ch.isspace() for ch in raw_url):
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        parsed = urlsplit(raw_url.strip())
        if parsed.scheme.lower() != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        if parsed.port not in (None, 443):
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        host = parsed.hostname.rstrip('.').lower()
        try:
            ipaddress.ip_address(host)
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        except ValueError:
            pass
        if host not in self.allowed_hosts:
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        if self.dns_resolver is not None:
            ips = self.dns_resolver(host)
        else:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            ips = [item[4][0] for item in infos]
        if not ips:
            raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        for ip_str in ips:
            allowed, _reason = classify_ip_ssrf(ip_str)
            if not allowed:
                raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403, details=audit_detail)
        return raw_url.strip(), host

    def _fetch_verified_bytes(self, source_url: str, bearer_token: str | None = None) -> bytes:
        current_url = source_url
        origin = urlsplit(source_url)
        send_auth = bool(bearer_token)
        for hop in range(MAX_REDIRECTS + 1):
            clean_url, host = self._validate_url_ssrf(current_url)
            cur_parsed = urlsplit(clean_url)
            if hop > 0 and (cur_parsed.hostname or '').lower() != (origin.hostname or '').lower():
                send_auth = False
            headers: dict[str, str] = {'User-Agent': 'VerdantFlare-ModelProvisioner/1.0'}
            if send_auth and bearer_token:
                headers['Authorization'] = f'Bearer {bearer_token}'
            if self.upstream_fetcher is None:
                raise Error('MODEL_DOWNLOAD_FAILED', 502)
            status_code, resp_headers, body = self.upstream_fetcher(clean_url, headers)
            if status_code in (301, 302, 303, 307, 308):
                if hop == MAX_REDIRECTS:
                    raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403)
                loc = (resp_headers.get('Location') or resp_headers.get('location') or '').strip()
                if not loc:
                    raise Error('MODEL_DOWNLOAD_FAILED', 502)
                next_url = urljoin(clean_url, loc)
                if (urlsplit(next_url).hostname or '').lower() != host:
                    send_auth = False
                current_url = next_url
                continue
            if status_code != 200:
                raise Error('MODEL_DOWNLOAD_FAILED', 502)
            return body
        raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403)

    def ensure_model(
        self,
        *,
        organization_id: str,
        project_id: str,
        principal_id: str,
        idempotency_key: str,
        model_id: str,
        target_alias: str = 'default',
        catalog_code: str | None = None,
        expected_sha256: str | None = None,
        bearer_token: str | None = None,
    ) -> dict[str, Any]:
        req_sha = hashlib.sha256(canonical({
            'model_id': model_id,
            'catalog_code': catalog_code or '',
            'expected_sha256': (expected_sha256 or '').lower(),
        }).encode('utf-8')).hexdigest()

        now = self.clock()
        alias_scope = target_alias.strip() if isinstance(target_alias, str) and target_alias.strip() else 'default'
        idem_scope = (organization_id, project_id, principal_id, alias_scope, idempotency_key)
        with self._lock:
            prev = self._idem.get(idem_scope)
            if prev is not None:
                if prev[2] <= now:
                    self._idem.pop(idem_scope, None)
                else:
                    if prev[0] != req_sha:
                        raise Error('IDEMPOTENCY_CONFLICT', 409)
                    replay = dict(prev[1])
                    replay['deduplicated'] = True
                    replay['model'] = self.get_model_status(model_id)
                    return replay

            entry = self._catalog_by_id.get(model_id)
            if entry is None:
                raise Error('MODEL_NOT_FOUND', 404)
            if catalog_code and catalog_code != entry['catalog_code']:
                raise Error('INVALID_PARAMETERS', 400)
            if entry['paid_access'] or entry['license_tier'] == LICENSE_TIER_PAID_FORBIDDEN:
                raise Error('MODEL_PAID_ACCESS_FORBIDDEN', 403)
            if expected_sha256 and expected_sha256.lower() != entry['sha256']:
                raise Error('MODEL_CATALOG_SHA256_MISMATCH', 409)
            validate_safetensors_filename(entry['filename'])
            if entry['approval_state'] == 'rejected':
                raise Error('MODEL_APPROVAL_REJECTED', 403)
            if (entry['origin_kind'] == 'local' or entry['license_tier'] == LICENSE_TIER_RESEARCH_NON_COMMERCIAL) and entry['approval_state'] != 'approved':
                # Pending approval MUST NOT seal idempotency so post-approval retry succeeds (T32-M03).
                return {
                    'code': 'MODEL_APPROVAL_REQUIRED',
                    'deduplicated': False,
                    'model': self._status_view_locked(entry),
                    'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
                }

            blob = self._blobs_by_sha[entry['sha256']]
            if blob['status'] == 'evicting':
                raise Error('MODEL_NOT_READY', 409)
            rel_view = f"{MODEL_CATEGORY_DIRS[entry['category']]}/{entry['sha256'][:12]}__{entry['filename']}"
            if blob['status'] == 'ready' and rel_view in blob.get('published_views', ()):
                self._publish_view_locked(entry, blob['download_fence'])
                resp = {
                    'deduplicated': True,
                    'model': self._status_view_locked(entry),
                    'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
                }
                self._idem[idem_scope] = (req_sha, resp, now + 86400)
                return resp

            if not entry['source_urls']:
                raise Error('MODEL_SOURCE_SSRF_BLOCKED', 403)
            self._validate_url_ssrf(entry['source_urls'][0])

            if blob['status'] == 'ready':
                self._publish_view_locked(entry, blob['download_fence'])
                resp = {
                    'deduplicated': True,
                    'model': self._status_view_locked(entry),
                    'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
                }
                self._idem[idem_scope] = (req_sha, resp, now + 86400)
                return resp

            if entry['size_bytes'] > self.max_auto_pull_bytes and not entry['source_policy'].get('large_model_approved'):
                return {
                    'code': 'MODEL_APPROVAL_REQUIRED',
                    'deduplicated': False,
                    'model': self._status_view_locked(entry),
                    'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
                }

            unmaterialized_other = sum(
                max(0, b['size_bytes'] - b['part_bytes_on_disk'])
                for s, b in self._blobs_by_sha.items()
                if s != entry['sha256'] and b['status'] in ('queued', 'downloading', 'verifying_sha256')
            )
            free_bytes = self.free_bytes_fn()
            reusable = blob['part_bytes_on_disk'] if (blob.get('etag') and 0 < blob['part_bytes_on_disk'] < entry['size_bytes']) else 0
            needed = entry['size_bytes'] - reusable
            if free_bytes - unmaterialized_other - needed < self.reserved_headroom_bytes:
                return {
                    'code': 'MODEL_APPROVAL_REQUIRED',
                    'deduplicated': False,
                    'model': self._status_view_locked(entry),
                    'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
                }

            blob['download_fence'] += 1
            fence = blob['download_fence']
            blob['status'] = 'downloading'

        part_path = self.root_dir / '.staging' / f"{entry['sha256']}.{fence}.part"
        try:
            body = self._fetch_verified_bytes(entry['source_urls'][0], bearer_token=bearer_token)
            if len(body) != entry['size_bytes']:
                raise Error('MODEL_SHA256_MISMATCH', 422)
            part_path.write_bytes(body)
            actual_sha = hashlib.sha256(body).hexdigest()
            if actual_sha != entry['sha256']:
                part_path.unlink(missing_ok=True)
                raise Error('MODEL_SHA256_MISMATCH', 422)
            validate_safetensors_bytes_or_file(part_path, entry['size_bytes'])
        except Error as exc:
            part_path.unlink(missing_ok=True)
            with self._lock:
                if blob['download_fence'] == fence and blob['status'] not in ('ready', 'evicting'):
                    blob['status'] = 'failed'
                    blob['last_error_code'] = exc.code
            raise

        with self._lock:
            if blob['download_fence'] != fence or blob['status'] in ('ready', 'evicting'):
                part_path.unlink(missing_ok=True)
            else:
                cas_path = self.root_dir / 'cas' / entry['sha256']
                if not cas_path.exists():
                    shutil.move(str(part_path), str(cas_path))
                else:
                    part_path.unlink(missing_ok=True)
                self._publish_view_locked(entry, fence)
                blob['status'] = 'ready'
                blob['bytes_downloaded'] = entry['size_bytes']
                blob['part_bytes_on_disk'] = 0
                blob['eta_seconds'] = 0
                blob['last_error_code'] = None
                blob['last_error_message'] = None

            resp = {
                'deduplicated': False,
                'model': self._status_view_locked(entry),
                'canonical_lock': normalize_canonical_model_lock_items([entry])[0],
            }
            self._idem[idem_scope] = (req_sha, resp, now + 86400)
            return resp

    def _publish_view_locked(self, entry: dict[str, Any], fence: int) -> str:
        cas_path = self.root_dir / 'cas' / entry['sha256']
        rel = relative_view_path(entry['category'], entry['sha256'], entry['filename'])
        view_path = self.root_dir / 'views' / rel
        view_path.parent.mkdir(parents=True, exist_ok=True)
        if not view_path.exists():
            tmp_link = self.root_dir / 'views' / f".tmp.{entry['sha256'][:12]}.{fence}"
            tmp_link.unlink(missing_ok=True)
            os.link(cas_path, tmp_link)
            os.replace(tmp_link, view_path)
        blob = self._blobs_by_sha[entry['sha256']]
        if rel not in blob['published_views']:
            blob['published_views'].append(rel)
        return rel

    def evict_model(self, sha256_hex: str) -> dict[str, Any]:
        sha = sha256_hex.strip().lower()
        with self._lock:
            blob = self._blobs_by_sha.get(sha)
            if blob is None:
                raise Error('MODEL_NOT_FOUND', 404)
            active, reserved = self._pin_counts_locked(sha)
            if active > 0 or reserved > 0:
                raise Error('MODEL_IN_USE', 409, details={'active_pins': active, 'reserved_pins': reserved})
            blob['status'] = 'evicting'
            for rel in list(blob['published_views']):
                (self.root_dir / 'views' / rel).unlink(missing_ok=True)
            (self.root_dir / 'cas' / sha).unlink(missing_ok=True)
            blob['published_views'] = []
            blob['status'] = 'not_installed'
            blob['bytes_downloaded'] = 0
            blob['part_bytes_on_disk'] = 0
            return {'sha256': sha, 'status': 'not_installed', 'download_fence': blob['download_fence']}

    def reserve_pins(
        self,
        *,
        reservation_id: str,
        operation_id: str,
        scope_kind: str,
        owner_id: str,
        organization_id: str,
        project_id: str,
        request_sha256: str,
        sha256_list: list[str],
        ttl_seconds: int = 60,
    ) -> dict[str, Any]:
        with self._lock:
            if reservation_id in self._revoked_tombstones:
                raise Error('ADMISSION_RESERVATION_EXPIRED', 409)
            existing = self._pins_by_res.get(reservation_id)
            if existing is not None:
                if existing.request_sha256 != request_sha256:
                    raise Error('IDEMPOTENCY_CONFLICT', 409)
                return {'reservation_id': reservation_id, 'state': existing.state}
            dedup_shas = sorted({s.lower() for s in sha256_list})
            for sha in dedup_shas:
                blob = self._blobs_by_sha.get(sha)
                if blob is None or blob['status'] != 'ready':
                    raise Error('MODEL_NOT_READY', 409)
            now_ts = self.clock()
            exp = now_ts + max(5, min(300, ttl_seconds))
            self._pins_by_res[reservation_id] = _PinGroup(
                reservation_id=reservation_id,
                operation_id=operation_id,
                scope_kind=scope_kind,
                owner_id=owner_id,
                organization_id=organization_id,
                project_id=project_id,
                request_sha256=request_sha256,
                sha256_list=dedup_shas,
                state='reserved',
                expires_at=exp,
                created_at=now_ts,
            )
            return {'reservation_id': reservation_id, 'state': 'reserved'}

    def commit_pins(self, *, reservation_id: str, owner_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if reservation_id in self._revoked_tombstones:
                raise Error('ADMISSION_RESERVATION_EXPIRED', 409)
            g = self._pins_by_res.get(reservation_id)
            if g is None:
                raise Error('ADMISSION_RESERVATION_EXPIRED', 409)
            g.state = 'active'
            g.expires_at = None
            if owner_id:
                g.owner_id = owner_id
            return {'reservation_id': reservation_id, 'state': 'active'}

    def release_pins(self, *, reservation_id: str, reason: str = '') -> dict[str, Any]:
        _ = reason
        with self._lock:
            removed = self._pins_by_res.pop(reservation_id, None)
            return {'reservation_id': reservation_id, 'released': 1 if removed is not None else 0}

    def reconcile_expired_pins(self, *, stale_task_age_seconds: float = 300.0) -> tuple[int, int]:
        """Run §4.3.3 cross-DB fence reconciliation: NEVER release on RPC error/timeout!"""
        now = self.clock()
        with self._lock:
            candidates = [
                (g.reservation_id, g.state)
                for g in self._pins_by_res.values()
                if (g.state == 'reserved' and g.expires_at is not None and g.expires_at <= now)
                or (g.state == 'active' and g.scope_kind == 'task_execution' and (now - g.created_at) >= stale_task_age_seconds)
            ]
        promoted = 0
        released = 0
        for res_id, prev_state in candidates:
            if self.revoker is None:
                continue
            try:
                verdict = self.revoker(res_id)
            except Exception:
                # Strict invariant: network/RPC timeout MUST NOT release reserved/active pins!
                continue
            state = verdict.get('state') if isinstance(verdict, dict) else None
            if state == 'committed':
                with self._lock:
                    g = self._pins_by_res.get(res_id)
                    if g is not None and g.state == 'reserved':
                        g.state = 'active'
                        g.expires_at = None
                        if verdict.get('entity_id'):
                            g.owner_id = str(verdict['entity_id'])
                        promoted += 1
            elif state == 'revoked' and prev_state == 'reserved':
                with self._lock:
                    self._pins_by_res.pop(res_id, None)
                    self._revoked_tombstones.add(res_id)
                    released += 1
            elif state == 'released':
                with self._lock:
                    if self._pins_by_res.pop(res_id, None) is not None:
                        released += 1
        return promoted, released


def execute_two_phase_model_admission(
    store,
    model_cache,
    *,
    scope_kind: str,
    organization_id: str,
    project_id: str,
    principal_id: str,
    request_sha256: str,
    sha256_list: list[str],
    in_tx_writer: Callable[[Any, str], tuple[str, Any] | tuple[str, Any, bool]],
    reservation_id: str | None = None,
    operation_id: str | None = None,
    ttl_seconds: int = 60,
):
    """Execute §4.3.3 two-phase cross-DB pin admission across Station PG and App SQLite."""
    res_id = reservation_id or f'mres-{request_id()}'
    op_id = operation_id or request_id()
    dedup_shas = sorted({s.strip().lower() for s in sha256_list if isinstance(s, str) and s.strip()})
    if not dedup_shas:
        with store.transaction() as db:
            writer_out = in_tx_writer(db, res_id)
            return writer_out[1]

    store.begin_model_admission_intent(
        reservation_id=res_id,
        operation_id=op_id,
        scope_kind=scope_kind,
        owner_id='pending',
        org_id=organization_id,
        project_id=project_id,
        principal_id=principal_id,
        request_sha256=request_sha256,
        model_sha256_list=dedup_shas,
    )
    try:
        model_cache.reserve_pins(
            reservation_id=res_id,
            operation_id=op_id,
            scope_kind=scope_kind,
            owner_id='pending',
            organization_id=organization_id,
            project_id=project_id,
            request_sha256=request_sha256,
            sha256_list=dedup_shas,
            ttl_seconds=ttl_seconds,
        )
    except BaseException:
        store.abort_model_admission_intent(res_id)
        raise

    entity_id = None
    replayed_existing = False
    try:
        with store.transaction() as db:
            writer_out = in_tx_writer(db, res_id)
            if len(writer_out) == 3:
                entity_id, result, replayed_existing = writer_out
            else:
                entity_id, result = writer_out
            if not replayed_existing:
                store.commit_model_admission_intent_in_tx(db, res_id, entity_id=entity_id)
    except TaskError as exc:
        if str(exc) == 'ADMISSION_RESERVATION_EXPIRED':
            raise Error('ADMISSION_RESERVATION_EXPIRED', 409) from None
        store.abort_model_admission_intent(res_id)
        try:
            model_cache.release_pins(reservation_id=res_id, reason='app_tx_aborted')
        except Exception:
            pass
        raise
    except BaseException:
        store.abort_model_admission_intent(res_id)
        try:
            model_cache.release_pins(reservation_id=res_id, reason='app_tx_aborted')
        except Exception:
            pass
        raise

    if replayed_existing:
        store.abort_model_admission_intent(res_id)
        try:
            model_cache.release_pins(reservation_id=res_id, reason='idempotent_replay_loser')
        except Exception:
            pass
        return result

    try:
        model_cache.commit_pins(reservation_id=res_id, owner_id=entity_id)
    except Error as exc:
        if exc.code == 'ADMISSION_RESERVATION_EXPIRED':
            raise
        # Network timeout after local SQLite COMMIT: Station reconciler will query
        # /internal/v1/model-admissions/revoke-or-verify, observe state == 'committed',
        # and promote reserved -> active without ever dropping the pin (§4.3.3 step 4a)!
    except Exception:
        pass
    return result
