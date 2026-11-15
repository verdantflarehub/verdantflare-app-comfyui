"""Bounded, boot-fenced, tenant-isolated ring buffer and multi-pass credential sanitizer.

Note: `worker/` and `app/` build into separate container images (`Dockerfile.worker` vs `Dockerfile`),
so `worker.log_ring` has zero imports from `app.*`; parity with `app.diagnostics` is enforced in tests.
"""
import base64
import codecs
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import html
import json
import re
import threading
import urllib.parse

MAX_RING_LINES = 5000
MAX_RING_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_DECODE_DEPTH = 4
MIN_RAW_TAIL_GUARD = 1024

UUID_RE = re.compile(
    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
)
HEX64_EXACT_RE = re.compile(r'^[0-9a-fA-F]{64}\Z')
SHA256_PREFIXED_RE = re.compile(r'\bsha256:[0-9a-fA-F]{64}\b', re.IGNORECASE)
REDACTED_MARKER_RE = re.compile(r'\[REDACTED(?:_PATH)?\]')

PEM_BLOCK_RE = re.compile(
    r'-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 _-]*PRIVATE KEY-----'
)
AUTH_HEADER_RE = re.compile(
    r'(Authorization\s*[:=]\s*)(?:(?:Bearer|Basic|Token|Digest)\s+)?(?:\\"|["\'])?[^\x00\s&\'",;)\]}\\]+(?:\\"|["\'])?',
    re.IGNORECASE,
)
COOKIE_HEADER_RE = re.compile(
    r'((?:Set-)?Cookie\s*[:=]\s*)[^\x00\r\n"\']+',
    re.IGNORECASE,
)
API_KEY_HEADER_RE = re.compile(
    r'(X-(?:Api-Key|Auth-Token|Access-Token|Service-Token|Worker-Token)\b\s*(?:[:=]|\s+)\s*)'
    r'(?:\\"|["\'])?[^\x00\s&\'",;)\]}\\]+(?:\\"|["\'])?',
    re.IGNORECASE,
)
BEARER_RE = re.compile(
    r'(Bearer\s+)(?:\\"|["\'])?[A-Za-z0-9._~+/=%-]{8,}(?:\\"|["\'])?',
    re.IGNORECASE,
)
X_VF_HEADER_RE = re.compile(
    r'(X-VF-(?:Worker-Token|Service-Token|Auth|Secret|Key|Token|Signature)[A-Za-z0-9_-]*\s*(?:[:=]|\s+)\s*'
    r'|X-VF-[A-Za-z0-9_-]*Token[A-Za-z0-9_-]*\s*(?:[:=]|\s+)\s*)'
    r'(?:\\"|["\'])?[^\x00\s&\'",;)\]}\\]+(?:\\"|["\'])?',
    re.IGNORECASE,
)
DSN_USERINFO_RE = re.compile(
    r'\b((?:postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?|https?)://)'
    r'[^\x00\s/@\'"]+:[^\x00\s@\'"]+@',
    re.IGNORECASE,
)
JSON_KV_SECRET_RE = re.compile(
    r'((?:\\"|")(?:'
    r'password|passwd|pwd|token|access_token|refresh_token|id_token|auth_token|'
    r'worker_token|app_token|runtime_token|authority_token|project_token|installation_token|'
    r'residency_token|service_token|vf_session|session_token|'
    r'secret|client_secret|aws_secret_access_key|api_key|apikey|key|'
    r'signature|sig|x-amz-signature|x-amz-security-token|authorization|'
    r'(?!(?:idempotency|request|cache|sort|group|node|input|output|primary|foreign|partition|routing)_key(?:\\"|"))'
    r'[A-Za-z0-9_-]+_(?:key|token|secret|password|passwd)'
    r')(?:\\"|")\s*:\s*)(?:\\"|")(?:[^"\x00\\]|\\.)*(?:\\"|")',
    re.IGNORECASE,
)
KV_SECRET_RE = re.compile(
    r'((?:'
    r'password|passwd|token|access_token|refresh_token|id_token|auth_token|'
    r'worker_token|app_token|runtime_token|authority_token|project_token|installation_token|'
    r'residency_token|service_token|vf_session|session_token|'
    r'secret|client_secret|aws_secret_access_key|api_key|apikey|'
    r'signature|x-amz-signature|x-amz-credential|x-amz-security-token'
    r'|(?:[?&]|\b)(?:pwd|sig)'
    r'|\b(?!(?:idempotency|request|cache|sort|group|node|input|output|primary|foreign|partition|routing)_key\b)'
    r'[A-Za-z0-9_-]+_(?:key|token|secret|password|passwd)'
    r')\s*(?:=|:)\s*'
    r'|[?&]key\s*=\s*)'
    r'((?:\\"|["\'])?)([^\x00\s&\'",;)\]}\\]+)(\2)',
    re.IGNORECASE,
)
SPACE_KV_SECRET_RE = re.compile(
    r'(\b(?:'
    r'password|passwd|worker_token|app_token|runtime_token|authority_token|'
    r'project_token|installation_token|residency_token|service_token|'
    r'access_token|refresh_token|auth_token|client_secret|aws_secret_access_key|'
    r'api_key|apikey|'
    r'(?!(?:idempotency|request|cache|sort|group|node|input|output|primary|foreign|partition|routing)_key\b)'
    r'[A-Za-z0-9_-]+_(?:key|token|secret|password|passwd)'
    r')[ \t]+)(?=[A-Za-z0-9._~+/=-]{8,})([^\x00\s&\'",;)\]}\\]+)',
    re.IGNORECASE,
)
KNOWN_KEY_PREFIX_RE = re.compile(
    r'\b(?:'
    r'sk-[A-Za-z0-9_-]{12,}'
    r'|sk_(?:live|test|canary)_[A-Za-z0-9_-]{10,}'
    r'|vf_(?:secret|tok|token|key|pat|live|test|canary)[A-Za-z0-9_-]{8,}'
    r'|vf-(?:secret|token|canary)-[A-Za-z0-9_-]{8,}'
    r'|ghp_[A-Za-z0-9]{16,}'
    r'|github_pat_[A-Za-z0-9_]{16,}'
    r'|hf_[A-Za-z0-9]{16,}'
    r'|xox[baprs]-[A-Za-z0-9-]{12,}'
    r'|AKIA[0-9A-Z]{16}'
    r'|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    r')\b'
)
HOST_PATH_RE = re.compile(
    r'(?:'
    r'/mnt/[A-Za-z]/[^\s:\'",;)\]}]+'
    r'|\\\\[A-Za-z0-9._-]+\\[^\s\'",;)\]}]+'
    r'|[A-Za-z]:\\[^\s\'",;)\]}]+'
    r'|[A-Za-z]:/[A-Za-z0-9._-]+(?:/[^\s\'",;)\]}]*)*'
    r'|/home/[A-Za-z0-9._-]+(?:/[^\s:\'",;)\]}]*)*'
    r'|/root(?:/[^\s:\'",;)\]}]+)+'
    r'|/Users/[A-Za-z0-9._-]+(?:/[^\s:\'",;)\]}]*)*'
    r'|/tmp/[^\s:\'",;)\]}]+'
    r'|/opt/[^\s:\'",;)\]}]+'
    r'|/proc/[0-9]+/[^\s:\'",;)\]}]+'
    r'|/var/lib/kubelet(?:/[^\s:\'",;)\]}]+)+'
    r'|/(?:var/)?run/secrets(?:/[^\s:\'",;)\]}]+)+'
    r'|/etc/kubernetes(?:/[^\s:\'",;)\]}]+)+'
    r'|/data/models(?:/[^\s:\'",;)\]}]+)+'
    r')'
)

PCT_SPAN_RE = re.compile(r'[A-Za-z0-9_~.:/+=-]*(?:%[0-9A-Fa-f]{2})+[A-Za-z0-9_~.:/%+=-]*')
UNICODE_ESC_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})+')
ESC_SPAN_RE = re.compile(r'[A-Za-z0-9_~.:/+=-]*(?:(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})[A-Za-z0-9_~.:/+=-]*)+')
CANDIDATE_TOKEN_RE = re.compile(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])')

TRAILING_SECRET_KEYWORD_RE = re.compile(
    r'(?:Authorization|Bearer|Basic|Token|Digest|Cookie|Set-Cookie'
    r'|X-[A-Za-z0-9_-]+'
    r'|password|passwd|pwd|token|access_token|refresh_token|id_token|auth_token'
    r'|worker_token|app_token|runtime_token|authority_token|project_token|installation_token'
    r'|residency_token|service_token|vf_session|session_token'
    r'|secret|client_secret|aws_secret_access_key|api_key|apikey|key'
    r'|signature|sig|x-amz-signature|x-amz-credential|x-amz-security-token'
    r'|[A-Za-z0-9_-]+_(?:key|token|secret|password|passwd))'
    r'(?:\\"|["\'\s:=])*(?:(?:Bearer|Basic|Token|Digest)(?:\\"|["\'\s:=])*)?$',
    re.IGNORECASE,
)

D4A_STATIC_NODE_CATALOG = {
    'CheckpointLoaderSimple': {
        'display_name': 'Load Checkpoint',
        'category': 'loaders',
        'input': {'required': {'ckpt_name': [['sd_xl_base_1.0.safetensors']]}},
        'output': ['MODEL', 'CLIP', 'VAE'],
    },
    'UNETLoader': {
        'display_name': 'Load Diffusion Model',
        'category': 'advanced/loaders',
        'input': {'required': {'unet_name': [[]], 'weight_dtype': [['default', 'fp8_e4m3fn']]}},
        'output': ['MODEL'],
    },
    'DualCLIPLoader': {
        'display_name': 'DualCLIPLoader',
        'category': 'advanced/loaders',
        'input': {'required': {'clip_name1': [[]], 'clip_name2': [[]], 'type': [['sdxl', 'flux']]}},
        'output': ['CLIP'],
    },
    'VAELoader': {
        'display_name': 'Load VAE',
        'category': 'loaders',
        'input': {'required': {'vae_name': [[]]}},
        'output': ['VAE'],
    },
    'LoraLoader': {
        'display_name': 'Load LoRA',
        'category': 'loaders',
        'input': {
            'required': {
                'model': ['MODEL'],
                'clip': ['CLIP'],
                'lora_name': [[]],
                'strength_model': ['FLOAT', {'default': 1.0, 'min': -10.0, 'max': 10.0}],
                'strength_clip': ['FLOAT', {'default': 1.0, 'min': -10.0, 'max': 10.0}],
            }
        },
        'output': ['MODEL', 'CLIP'],
    },
    'CLIPTextEncode': {
        'display_name': 'CLIP Text Encode (Prompt)',
        'category': 'conditioning',
        'input': {'required': {'text': ['STRING', {'multiline': True}], 'clip': ['CLIP']}},
        'output': ['CONDITIONING'],
    },
    'EmptyLatentImage': {
        'display_name': 'Empty Latent Image',
        'category': 'latent',
        'input': {
            'required': {
                'width': ['INT', {'default': 1024, 'min': 64, 'max': 4096, 'step': 8}],
                'height': ['INT', {'default': 1024, 'min': 64, 'max': 4096, 'step': 8}],
                'batch_size': ['INT', {'default': 1, 'min': 1, 'max': 16}],
            }
        },
        'output': ['LATENT'],
    },
    'LoadImage': {
        'display_name': 'Load Image',
        'category': 'image',
        'input': {'required': {'image': [[]]}},
        'output': ['IMAGE', 'MASK'],
    },
    'KSampler': {
        'display_name': 'KSampler',
        'category': 'sampling',
        'input': {
            'required': {
                'model': ['MODEL'],
                'seed': ['INT', {'default': 0, 'min': 0, 'max': 9007199254740991}],
                'steps': ['INT', {'default': 20, 'min': 1, 'max': 100}],
                'cfg': ['FLOAT', {'default': 7.0, 'min': 0.0, 'max': 30.0}],
                'sampler_name': [['euler', 'euler_ancestral', 'dpmpp_2m', 'lcm']],
                'scheduler': [['normal', 'karras', 'sgm_uniform', 'simple']],
                'positive': ['CONDITIONING'],
                'negative': ['CONDITIONING'],
                'latent_image': ['LATENT'],
                'denoise': ['FLOAT', {'default': 1.0, 'min': 0.0, 'max': 1.0}],
            }
        },
        'output': ['LATENT'],
    },
    'VAEDecode': {
        'display_name': 'VAE Decode',
        'category': 'latent',
        'input': {'required': {'samples': ['LATENT'], 'vae': ['VAE']}},
        'output': ['IMAGE'],
    },
    'SaveImage': {
        'display_name': 'Save Image',
        'category': 'image',
        'input': {'required': {'images': ['IMAGE'], 'filename_prefix': ['STRING', {'default': 'ComfyUI'}]}},
        'output': [],
        'output_node': True,
    },
    'ControlNetLoader': {
        'display_name': 'Load ControlNet Model',
        'category': 'loaders',
        'input': {'required': {'control_net_name': [[]]}},
        'output': ['CONTROL_NET'],
    },
    'ControlNetApplyAdvanced': {
        'display_name': 'Apply ControlNet',
        'category': 'conditioning/controlnet',
        'input': {
            'required': {
                'positive': ['CONDITIONING'],
                'negative': ['CONDITIONING'],
                'control_net': ['CONTROL_NET'],
                'image': ['IMAGE'],
                'strength': ['FLOAT', {'default': 1.0, 'min': 0.0, 'max': 2.0}],
                'start_percent': ['FLOAT', {'default': 0.0, 'min': 0.0, 'max': 1.0}],
                'end_percent': ['FLOAT', {'default': 1.0, 'min': 0.0, 'max': 1.0}],
            }
        },
        'output': ['CONDITIONING', 'CONDITIONING'],
    },
    'VHS_VideoCombine': {
        'display_name': 'Video Combine',
        'category': 'VideoHelperSuite',
        'input': {
            'required': {
                'images': ['IMAGE'],
                'frame_rate': ['FLOAT', {'default': 16.0, 'min': 1.0, 'max': 120.0}],
                'filename_prefix': ['STRING', {'default': 'AnimateDiff'}],
                'format': [['video/h264-mp4', 'video/webm']],
            }
        },
        'output': [],
        'output_node': True,
    },
}


def _is_printable_utf8(raw_bytes: bytes) -> str | None:
    if not raw_bytes:
        return None
    try:
        decoded = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if all(ch in '\t\r\n' or (32 <= ord(ch) <= 126) for ch in decoded):
        return decoded
    return None


def _has_direct_secret(text: str, exact_secrets: tuple[str, ...] = ()) -> bool:
    if any(sec and sec in text for sec in exact_secrets):
        return True
    return bool(
        PEM_BLOCK_RE.search(text)
        or AUTH_HEADER_RE.search(text)
        or COOKIE_HEADER_RE.search(text)
        or API_KEY_HEADER_RE.search(text)
        or BEARER_RE.search(text)
        or X_VF_HEADER_RE.search(text)
        or DSN_USERINFO_RE.search(text)
        or JSON_KV_SECRET_RE.search(text)
        or KV_SECRET_RE.search(text)
        or SPACE_KV_SECRET_RE.search(text)
        or KNOWN_KEY_PREFIX_RE.search(text)
    )


def _decode_variants(token: str) -> list[str]:
    variants = []
    if '%' in token:
        unquoted = urllib.parse.unquote(token)
        if unquoted != token:
            variants.append(unquoted)
    if '\\u' in token or '\\x' in token:
        def _unesc(match):
            seq = match.group(0)
            try:
                return bytes(seq, 'ascii').decode('unicode_escape')
            except Exception:
                return seq
        unescaped = UNICODE_ESC_RE.sub(_unesc, token)
        if unescaped != token:
            variants.append(unescaped)
    if '&#' in token or '&amp;' in token:
        unesc_html = html.unescape(token)
        if unesc_html != token:
            variants.append(unesc_html)
    stripped = token.strip()
    if len(stripped) >= 16 and len(stripped) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', stripped):
        try:
            text = _is_printable_utf8(bytes.fromhex(stripped))
            if text is not None:
                variants.append(text)
        except ValueError:
            pass
    if len(stripped) >= 16 and re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}', stripped):
        padded = stripped + ('=' * ((4 - len(stripped) % 4) % 4))
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded.encode('ascii'))
            except Exception:
                continue
            text = _is_printable_utf8(raw)
            if text is not None and text != stripped and text not in variants:
                variants.append(text)
    return variants


def _encoded_contains_secret(token: str, depth: int, preserve_lower: set[str],
                             exact_secrets: tuple[str, ...] = ()) -> bool:
    if depth > MAX_DECODE_DEPTH or not token:
        return False
    low = token.lower()
    if low in preserve_lower or SHA256_PREFIXED_RE.fullmatch(token):
        return False
    if depth == 0 and UUID_RE.fullmatch(token):
        return False
    if _has_direct_secret(token, exact_secrets):
        return True
    for decoded in _decode_variants(token):
        if _has_direct_secret(decoded, exact_secrets):
            return True
        if depth + 1 <= MAX_DECODE_DEPTH:
            if _encoded_contains_secret(decoded, depth + 1, preserve_lower, exact_secrets):
                return True
            for match in CANDIDATE_TOKEN_RE.finditer(decoded):
                if _encoded_contains_secret(match.group(0), depth + 1, preserve_lower, exact_secrets):
                    return True
            for match in PCT_SPAN_RE.finditer(decoded):
                if _encoded_contains_secret(match.group(0), depth + 1, preserve_lower, exact_secrets):
                    return True
    return False


def sanitize_text(text: str, *, preserve_hashes=(), exact_secrets=()) -> str:
    """Sanitize credentials, multi-encoded secrets, and host paths while preserving UUIDs & known SHA-256."""
    if not isinstance(text, str) or not text:
        return text
    secret_tuple = tuple(sorted({s for s in exact_secrets if isinstance(s, str) and len(s) >= 8}, key=len, reverse=True))
    preserve_lower = {
        h.lower()
        for h in preserve_hashes
        if isinstance(h, str) and HEX64_EXACT_RE.fullmatch(h) and not _encoded_contains_secret(h, 0, set(), secret_tuple)
    }

    protected = {}

    def _stash(val: str) -> str:
        idx = len(protected)
        placeholder = f'\x00VFKEEP{idx}END\x00'
        protected[placeholder] = val
        return placeholder

    work = text
    for sec in secret_tuple:
        work = work.replace(sec, '[REDACTED]')
    work = REDACTED_MARKER_RE.sub(lambda m: _stash(m.group(0)), work)

    def _replace_encoded_span(match):
        span = match.group(0)
        if '\x00VFKEEP' in span:
            return span
        return '[REDACTED]' if _encoded_contains_secret(span, 0, preserve_lower, secret_tuple) else span

    work = ESC_SPAN_RE.sub(_replace_encoded_span, work)
    work = PEM_BLOCK_RE.sub('[REDACTED]', work)
    work = AUTH_HEADER_RE.sub(r'\1[REDACTED]', work)
    work = COOKIE_HEADER_RE.sub(r'\1[REDACTED]', work)
    work = API_KEY_HEADER_RE.sub(r'\1[REDACTED]', work)
    work = BEARER_RE.sub(r'\1[REDACTED]', work)
    work = X_VF_HEADER_RE.sub(r'\1[REDACTED]', work)
    work = DSN_USERINFO_RE.sub(r'\1[REDACTED]@', work)
    work = JSON_KV_SECRET_RE.sub(r'\1"[REDACTED]"', work)
    work = KV_SECRET_RE.sub(lambda m: f'{m.group(1)}{m.group(2)}[REDACTED]{m.group(4)}', work)
    work = SPACE_KV_SECRET_RE.sub(r'\1[REDACTED]', work)
    work = KNOWN_KEY_PREFIX_RE.sub('[REDACTED]', work)
    work = PCT_SPAN_RE.sub(_replace_encoded_span, work)

    work = SHA256_PREFIXED_RE.sub(lambda m: _stash(m.group(0)), work)
    work = UUID_RE.sub(lambda m: _stash(m.group(0)), work)
    for digest in sorted(preserve_lower, key=len, reverse=True):
        work = re.sub(re.escape(digest), lambda m: _stash(m.group(0)), work, flags=re.IGNORECASE)

    def _replace_token(match):
        tok = match.group(0)
        if '\x00VFKEEP' in tok:
            return tok
        if HEX64_EXACT_RE.fullmatch(tok):
            return tok if tok.lower() in preserve_lower else '[REDACTED]'
        if _encoded_contains_secret(tok, 0, preserve_lower, secret_tuple):
            return '[REDACTED]'
        return tok

    work = CANDIDATE_TOKEN_RE.sub(_replace_token, work)
    work = HOST_PATH_RE.sub('[REDACTED_PATH]', work)

    for placeholder, original in protected.items():
        work = work.replace(placeholder, original)
    return work


MAX_ACTIVE_FRAMED_LANES = 64


class _StreamLane:
    __slots__ = ('utf8_decoder', 'buffer', 'context', 'line_tainted', 'drop_until_delimiter')

    def __init__(self, context: tuple[str | None, str | None] = (None, None)):
        self.utf8_decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.buffer = ''
        self.context = context
        self.line_tainted = False
        self.drop_until_delimiter = False


class ChunkedStreamIngestor:
    """Reassembles arbitrary byte/text chunks across transport packet & line boundaries without leaking split secrets."""

    def __init__(self, ring, stream: str, *, project_id=None, task_id=None,
                 context_provider=None, frame_nonce: str | None = None,
                 frame_resolver=None, max_line_chars=8192):
        self.ring = ring
        self.stream = stream
        self.project_id = project_id
        self.task_id = task_id
        self.context_provider = context_provider
        self.frame_nonce = frame_nonce if (isinstance(frame_nonce, str) and len(frame_nonce) >= 8) else None
        self.frame_resolver = frame_resolver
        nonce_bytes = self.frame_nonce.encode('ascii', errors='ignore') if self.frame_nonce is not None else None
        self._nonce_bytes = nonce_bytes if nonce_bytes else None
        self._frame_re_bytes = (
            re.compile(rb'\x00VF_CTX:' + re.escape(self._nonce_bytes) + rb':([A-Za-z0-9_.:-]{1,128}):(BEGIN|END|FLUSH)\x00(?:\r?\n)?')
            if self._nonce_bytes is not None
            else None
        )
        self.max_line_chars = max_line_chars
        self._unframed_lane = _StreamLane((None, None))
        self._framed_lanes: dict[str, _StreamLane] = {}
        self._active_frame_pid: str | None = None
        self._byte_carry = b''

    def _resolve_unframed_context(self) -> tuple[str | None, str | None]:
        if self._frame_re_bytes is not None:
            return None, None
        if self.project_id is not None or self.task_id is not None:
            return self.project_id, self.task_id
        if self.context_provider is not None:
            ctx = self.context_provider()
            if isinstance(ctx, tuple) and len(ctx) == 2:
                return ctx
        return None, None

    def taint_pending(self):
        """Taint any buffered half-line before an unframed context transition."""
        if self._unframed_lane.buffer and self._frame_re_bytes is None:
            self._unframed_lane.line_tainted = True
            self._unframed_lane.context = (None, None)

    def _emit_line_with_context(self, raw_line: str, ctx: tuple[str | None, str | None]):
        proj, tid = ctx
        self.ring.append(self.stream, raw_line, project_id=proj, task_id=tid)

    def _feed_lane_text(self, lane: _StreamLane, chunk: str, chunk_ctx: tuple[str | None, str | None]):
        if not chunk:
            return
        if lane.drop_until_delimiter:
            m = re.search(r'[\s&\'",;)\]}]', chunk)
            if not m:
                return
            chunk = chunk[m.start():]
            lane.drop_until_delimiter = False

        if not lane.buffer:
            lane.context = chunk_ctx
            lane.line_tainted = False
        elif chunk_ctx != lane.context:
            lane.line_tainted = True

        lane.buffer += chunk
        while '\n' in lane.buffer:
            line, lane.buffer = lane.buffer.split('\n', 1)
            emit_ctx = (None, None) if lane.line_tainted else lane.context
            self._emit_line_with_context(line.rstrip('\r'), emit_ctx)
            lane.context = chunk_ctx
            lane.line_tainted = False

        tail_guard = max(MIN_RAW_TAIL_GUARD, min(4096, self.max_line_chars // 2))
        while len(lane.buffer) > self.max_line_chars + tail_guard:
            safe_limit = min(self.max_line_chars, len(lane.buffer) - tail_guard)
            cut = -1
            search_end = safe_limit
            while search_end > 0:
                ws = max(lane.buffer.rfind(' ', 0, search_end), lane.buffer.rfind('\t', 0, search_end))
                if ws <= 0:
                    break
                prefix = lane.buffer[:ws]
                if not TRAILING_SECRET_KEYWORD_RE.search(prefix):
                    cut = ws + 1
                    break
                search_end = ws
            emit_ctx = (None, None) if lane.line_tainted else lane.context
            if cut > 0:
                raw_head, lane.buffer = lane.buffer[:cut], lane.buffer[cut:]
                self._emit_line_with_context(raw_head, emit_ctx)
                continue

            sanitized_probe = sanitize_text(
                lane.buffer,
                preserve_hashes=self.ring.preserve_hashes,
                exact_secrets=getattr(self.ring, 'exact_secrets', ()),
            )
            if '[REDACTED]' in sanitized_probe or '[REDACTED_PATH]' in sanitized_probe:
                self._emit_line_with_context('[REDACTED]', emit_ctx)
                lane.buffer = ''
                lane.context = chunk_ctx
                lane.line_tainted = False
                lane.drop_until_delimiter = True
                break
            raw_head, lane.buffer = lane.buffer[:safe_limit], lane.buffer[safe_limit:]
            self._emit_line_with_context(raw_head, emit_ctx)

    def _feed_lane_bytes(self, lane: _StreamLane, raw_bytes: bytes, chunk_ctx: tuple[str | None, str | None]):
        if not raw_bytes:
            return
        decoded = lane.utf8_decoder.decode(raw_bytes, final=False)
        if decoded:
            self._feed_lane_text(lane, decoded, chunk_ctx)

    def _flush_lane(self, lane: _StreamLane):
        rem = lane.utf8_decoder.decode(b'', final=True)
        if rem:
            self._feed_lane_text(lane, rem, lane.context)
        lane.drop_until_delimiter = False
        if lane.buffer:
            trailing = lane.buffer.rstrip('\r')
            emit_ctx = (None, None) if lane.line_tainted else lane.context
            lane.buffer = ''
            lane.context = (None, None)
            lane.line_tainted = False
            if trailing:
                self._emit_line_with_context(trailing, emit_ctx)

    def _route_payload_bytes(self, raw_bytes: bytes, *, explicit_context=None):
        if not raw_bytes:
            return
        if self._frame_re_bytes is None:
            ctx = explicit_context if explicit_context is not None else self._resolve_unframed_context()
            self._feed_lane_bytes(self._unframed_lane, raw_bytes, ctx)
            return
        if self._active_frame_pid is not None:
            lane = self._framed_lanes.get(self._active_frame_pid)
            if lane is not None:
                ctx = explicit_context if explicit_context is not None else lane.context
                self._feed_lane_bytes(lane, raw_bytes, ctx)
                return
        ctx = explicit_context if explicit_context is not None else (None, None)
        self._feed_lane_bytes(self._unframed_lane, raw_bytes, ctx)

    def _consume_bytes_with_frames(self, raw_bytes: bytes, *, final: bool, explicit_context=None):
        if self._frame_re_bytes is None:
            self._route_payload_bytes(raw_bytes, explicit_context=explicit_context)
            return

        data = self._byte_carry + raw_bytes
        self._byte_carry = b''
        prefix_marker_b = b'\x00VF_CTX:' + self._nonce_bytes + b':'
        max_frame_len = len(prefix_marker_b) + 145

        pos = 0
        n = len(data)
        while pos < n:
            nul_idx = data.find(b'\x00', pos)
            if nul_idx == -1:
                self._route_payload_bytes(data[pos:], explicit_context=explicit_context)
                break

            if nul_idx > pos:
                self._route_payload_bytes(data[pos:nul_idx], explicit_context=explicit_context)
                pos = nul_idx

            rem = data[pos:]
            m = self._frame_re_bytes.match(rem)
            if m is not None:
                if not final and (
                    (m.end() == len(rem) and not rem.endswith(b'\n'))
                    or (m.end() == len(rem) - 1 and rem.endswith(b'\r'))
                ):
                    self._byte_carry = rem
                    break
                pid = m.group(1).decode('ascii')
                action = m.group(2)
                if action == b'BEGIN':
                    resolved = self.frame_resolver(pid) if self.frame_resolver is not None else None
                    ctx = resolved if (isinstance(resolved, tuple) and len(resolved) == 2) else (None, None)
                    lane = self._framed_lanes.get(pid)
                    if lane is None:
                        if len(self._framed_lanes) >= MAX_ACTIVE_FRAMED_LANES:
                            oldest_pid, oldest_lane = next(iter(self._framed_lanes.items()))
                            del self._framed_lanes[oldest_pid]
                            self._flush_lane(oldest_lane)
                        lane = _StreamLane(ctx)
                        self._framed_lanes[pid] = lane
                    else:
                        del self._framed_lanes[pid]
                        self._framed_lanes[pid] = lane
                        if lane.context != ctx:
                            lane.line_tainted = True
                            lane.context = (None, None)
                    self._active_frame_pid = pid
                elif action == b'END':
                    self._active_frame_pid = None
                elif action == b'FLUSH':
                    if self._active_frame_pid == pid:
                        self._active_frame_pid = None
                    lane = self._framed_lanes.pop(pid, None)
                    if lane is not None:
                        self._flush_lane(lane)
                pos += m.end()
                continue

            if not final and len(rem) <= max_frame_len and (
                prefix_marker_b.startswith(rem)
                or (rem.startswith(prefix_marker_b) and b'\x00' not in rem[1:])
            ):
                self._byte_carry = rem
                break

            self._route_payload_bytes(b'\x00', explicit_context=explicit_context)
            pos += 1

    def feed(self, chunk: str | bytes, *, context: tuple[str | None, str | None] | None = None):
        if isinstance(chunk, str):
            raw_bytes = chunk.encode('utf-8', errors='replace')
        elif isinstance(chunk, (bytes, bytearray, memoryview)):
            raw_bytes = bytes(chunk)
        else:
            return
        if not raw_bytes:
            return
        self._consume_bytes_with_frames(raw_bytes, final=False, explicit_context=context)

    def flush(self):
        if self._byte_carry:
            self._consume_bytes_with_frames(b'', final=True)
        for lane in list(self._framed_lanes.values()):
            self._flush_lane(lane)
        self._framed_lanes.clear()
        self._active_frame_pid = None
        self._flush_lane(self._unframed_lane)


@dataclass(frozen=True)
class LogEntry:
    seq: int
    boot_id: str
    stream: str
    timestamp: str
    project_id: str | None
    task_id: str | None
    message: str
    byte_len: int


class RingQueryError(Exception):
    def __init__(self, code: str, status: int = 400, *, details: dict | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.details = details or {}


class LogRingBuffer:
    """Thread-safe bounded ring buffer per worker boot_id (<= 5000 lines, <= 4 MiB)."""

    def __init__(self, boot_id: str, *, max_lines: int = MAX_RING_LINES,
                 max_bytes: int = MAX_RING_BYTES, exact_secrets=()):
        self._lock = threading.Lock()
        self.boot_id = boot_id
        self.max_lines = max(1, int(max_lines))
        self.max_bytes = max(1024, int(max_bytes))
        self.preserve_hashes: set[str] = set()
        self.exact_secrets: set[str] = {s for s in exact_secrets if isinstance(s, str) and len(s) >= 8}
        self._entries: deque[LogEntry] = deque()
        self._total_bytes = 0
        self._next_seq = 1
        self.ring_dropped_count = 0

    def register_known_hashes(self, hashes):
        with self._lock:
            for item in hashes:
                if isinstance(item, str) and HEX64_EXACT_RE.fullmatch(item):
                    self.preserve_hashes.add(item.lower())

    def register_exact_secrets(self, secrets_iter):
        with self._lock:
            for item in secrets_iter:
                if isinstance(item, str) and len(item) >= 8:
                    self.exact_secrets.add(item)

    def reset(self, new_boot_id: str):
        with self._lock:
            self.boot_id = new_boot_id
            self._entries.clear()
            self._total_bytes = 0
            self._next_seq = 1
            self.ring_dropped_count = 0

    def append(self, stream: str, message: str, *, project_id: str | None = None,
               task_id: str | None = None, timestamp: str | None = None) -> int:
        if stream not in {'supervisor', 'engine'}:
            raise ValueError('invalid stream')
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._lock:
            clean_msg = sanitize_text(
                str(message),
                preserve_hashes=self.preserve_hashes,
                exact_secrets=self.exact_secrets,
            )
            if len(clean_msg) > 8192:
                clean_msg = clean_msg[:8192] + '...[TRUNCATED]'
            seq = self._next_seq
            self._next_seq += 1
            encoded_len = len(clean_msg.encode('utf-8')) + 96
            entry = LogEntry(
                seq=seq,
                boot_id=self.boot_id,
                stream=stream,
                timestamp=ts,
                project_id=project_id,
                task_id=task_id,
                message=clean_msg,
                byte_len=encoded_len,
            )
            self._entries.append(entry)
            self._total_bytes += encoded_len
            while len(self._entries) > self.max_lines or (
                    self._total_bytes > self.max_bytes and len(self._entries) > 1):
                dropped = self._entries.popleft()
                self._total_bytes -= dropped.byte_len
                self.ring_dropped_count += 1
            return seq

    def query(self, req_project_id: str, *, is_owner_or_admin: bool, stream: str = 'all',
              since_seq: int | None = None, tail_lines: int = 100,
              boot_id: str | None = None, task_id: str | None = None,
              max_response_bytes: int = MAX_RESPONSE_BYTES) -> dict:
        if stream not in {'all', 'supervisor', 'engine'}:
            raise RingQueryError('INVALID_PARAMETERS', 400)
        if type(tail_lines) is not int or not 1 <= tail_lines <= 500:
            raise RingQueryError('INVALID_PARAMETERS', 400)
        if since_seq is not None:
            if type(since_seq) is not int or since_seq < 0 or not boot_id:
                raise RingQueryError('INVALID_PARAMETERS', 400)

        with self._lock:
            current_boot = self.boot_id
            if boot_id is not None and boot_id != current_boot:
                raise RingQueryError('BOOT_ID_MISMATCH', 409, details={'current_boot_id': current_boot})

            first_avail = self._entries[0].seq if self._entries else 0
            last_avail = self._entries[-1].seq if self._entries else 0
            dropped_count = self.ring_dropped_count
            preserve = set(self.preserve_hashes)
            exact = tuple(self.exact_secrets)
            snapshot = list(self._entries)

        scope_included = 'project_and_instance_lifecycle' if is_owner_or_admin else 'project_only'
        filtered: list[LogEntry] = []
        for entry in snapshot:
            # L3 Hard Rule: entries tagged with ANY other project_id are unconditionally excluded
            # for ALL callers (including instance owner and organization admin).
            if entry.project_id is not None and entry.project_id != req_project_id:
                continue
            if entry.project_id is None:
                if entry.stream != 'supervisor' or not is_owner_or_admin:
                    continue
            if stream != 'all' and entry.stream != stream:
                continue
            if task_id is not None and entry.task_id != task_id:
                continue
            if since_seq is not None and entry.seq <= since_seq:
                continue
            filtered.append(entry)

        truncated = False
        if since_seq is not None:
            if dropped_count > 0 and first_avail > 0 and since_seq + 1 < first_avail:
                truncated = True
            if len(filtered) > tail_lines:
                filtered = filtered[:tail_lines]
                truncated = True
        else:
            if len(filtered) > tail_lines:
                filtered = filtered[-tail_lines:]
                truncated = True

        serialized_entries = []
        acc_bytes = 0
        if since_seq is not None:
            for entry in filtered:
                item = {
                    'seq': entry.seq,
                    'boot_id': entry.boot_id,
                    'stream': entry.stream,
                    'timestamp': entry.timestamp,
                    'project_id': entry.project_id,
                    'task_id': entry.task_id,
                    'message': sanitize_text(entry.message, preserve_hashes=preserve, exact_secrets=exact),
                }
                item_bytes = len(json.dumps(item, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
                if serialized_entries and acc_bytes + item_bytes > max_response_bytes:
                    truncated = True
                    break
                serialized_entries.append(item)
                acc_bytes += item_bytes
        else:
            kept_reversed = []
            for entry in reversed(filtered):
                item = {
                    'seq': entry.seq,
                    'boot_id': entry.boot_id,
                    'stream': entry.stream,
                    'timestamp': entry.timestamp,
                    'project_id': entry.project_id,
                    'task_id': entry.task_id,
                    'message': sanitize_text(entry.message, preserve_hashes=preserve, exact_secrets=exact),
                }
                item_bytes = len(json.dumps(item, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
                if kept_reversed and acc_bytes + item_bytes > max_response_bytes:
                    truncated = True
                    break
                kept_reversed.append(item)
                acc_bytes += item_bytes
            serialized_entries = list(reversed(kept_reversed))

        if serialized_entries:
            returned_from_seq = serialized_entries[0]['seq']
            next_seq = serialized_entries[-1]['seq']
        else:
            returned_from_seq = (since_seq + 1) if since_seq is not None else last_avail
            next_seq = max(last_avail, since_seq or 0)

        return {
            'boot_id': current_boot,
            'stream': stream,
            'scope_included': scope_included,
            'first_available_seq': first_avail,
            'last_available_seq': last_avail,
            'returned_from_seq': returned_from_seq,
            'next_seq': next_seq,
            'truncated': truncated,
            'ring_dropped_count': dropped_count,
            'entries': serialized_entries,
        }
