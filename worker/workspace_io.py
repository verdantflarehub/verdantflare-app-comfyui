"""Pure-stdlib container workspace FD I/O, media header inspection, and standby D4-A node catalog.

Note: `worker/` and `app/` build into separate container images (`Dockerfile.worker` vs `Dockerfile`),
and upstream ComfyUI inside `/opt/comfyui` owns its own top-level `app` package. Therefore `worker.*`
MUST NEVER import `app.*`; parity with `app.diagnostics` and `app.artifact_bridge` is enforced in tests.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import sys


class WorkspaceIOError(Exception):
    """Structured fail-closed error raised by worker workspace I/O helpers."""

    def __init__(self, code: str, status: int = 400, *, details: dict | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.details = details or {}


STANDBY_D4A_OBJECT_INFO = {
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
    'CLIPLoader': {
        'display_name': 'Load CLIP',
        'category': 'advanced/loaders',
        'input': {'required': {'clip_name': [[]], 'type': [['sdxl', 'sd3', 'flux', 'wan']]}},
        'output': ['CLIP'],
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
    'LoraLoaderModelOnly': {
        'display_name': 'LoraLoaderModelOnly',
        'category': 'loaders',
        'input': {
            'required': {
                'model': ['MODEL'],
                'lora_name': [[]],
                'strength_model': ['FLOAT', {'default': 1.0, 'min': -10.0, 'max': 10.0}],
            }
        },
        'output': ['MODEL'],
    },
    'UpscaleModelLoader': {
        'display_name': 'Load Upscale Model',
        'category': 'loaders',
        'input': {'required': {'model_name': [[]]}},
        'output': ['UPSCALE_MODEL'],
    },
    'IPAdapterModelLoader': {
        'display_name': 'IPAdapter Model Loader',
        'category': 'ipadapter',
        'input': {'required': {'ipadapter_file': [[]]}},
        'output': ['IPADAPTER'],
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
    'VAEEncode': {
        'display_name': 'VAE Encode',
        'category': 'latent',
        'input': {'required': {'pixels': ['IMAGE'], 'vae': ['VAE']}},
        'output': ['LATENT'],
    },
    'LoadImage': {
        'display_name': 'Load Image',
        'category': 'image',
        'input': {'required': {'image': [[]]}},
        'output': ['IMAGE', 'MASK'],
    },
    'LoadImageMask': {
        'display_name': 'Load Image (as Mask)',
        'category': 'mask',
        'input': {'required': {'image': [[]], 'channel': [['alpha', 'red', 'green', 'blue']]}},
        'output': ['MASK'],
    },
    'ImageScale': {
        'display_name': 'Upscale Image',
        'category': 'image/upscaling',
        'input': {
            'required': {
                'image': ['IMAGE'],
                'upscale_method': [['nearest-exact', 'bilinear', 'area', 'bicubic', 'lanczos']],
                'width': ['INT', {'default': 1024, 'min': 64, 'max': 4096, 'step': 8}],
                'height': ['INT', {'default': 1024, 'min': 64, 'max': 4096, 'step': 8}],
                'crop': [['disabled', 'center']],
            }
        },
        'output': ['IMAGE'],
    },
    'ImageUpscaleWithModel': {
        'display_name': 'Upscale Image (using Model)',
        'category': 'image/upscaling',
        'input': {'required': {'upscale_model': ['UPSCALE_MODEL'], 'image': ['IMAGE']}},
        'output': ['IMAGE'],
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
                'sampler_name': [['euler', 'euler_ancestral', 'dpmpp_2m', 'dpmpp_sde', 'lcm']],
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
    'VHS_LoadVideo': {
        'display_name': 'Load Video (Upload)',
        'category': 'VideoHelperSuite',
        'input': {
            'required': {
                'video': [[]],
                'force_rate': ['FLOAT', {'default': 0.0, 'min': 0.0, 'max': 120.0}],
                'custom_width': ['INT', {'default': 0, 'min': 0, 'max': 4096}],
                'custom_height': ['INT', {'default': 0, 'min': 0, 'max': 4096}],
                'frame_load_cap': ['INT', {'default': 0, 'min': 0, 'max': 1024}],
                'skip_first_frames': ['INT', {'default': 0, 'min': 0, 'max': 1024}],
                'select_every_nth': ['INT', {'default': 1, 'min': 1, 'max': 64}],
            }
        },
        'output': ['IMAGE', 'INT', 'AUDIO', 'VHS_VIDEOINFO'],
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

SAFE_TASK_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
SAFE_INPUT_FILENAME_RE = re.compile(r'^in_[0-9]{1,3}_[0-9a-f]{12,16}\.(?:png|jpg|webp|mp4|webm)\Z')
SAFE_OUTPUT_FILENAME_RE = re.compile(r'^(?:out_[1-9][0-9]{0,5}|output)_[0-9]+.*?\.(?:png|jpg|webp|mp4|webm)\Z')

SYS_OPENAT2 = 437
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ('flags', ctypes.c_uint64),
        ('mode', ctypes.c_uint64),
        ('resolve', ctypes.c_uint64),
    ]


_LIBC = None
if sys.platform.startswith('linux') and os.uname().machine in ('x86_64', 'aarch64'):
    try:
        _LIBC = ctypes.CDLL(None, use_errno=True)
        _LIBC.syscall.restype = ctypes.c_long
    except Exception:
        _LIBC = None


def _reject_unsafe_segment(segment: str, pattern: re.Pattern[str] | None = None) -> None:
    if not isinstance(segment, str) or not segment:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSAFE_PATH_SEGMENT'})
    low = segment.lower()
    if (
        '/' in segment
        or '\\' in segment
        or '..' in segment
        or '\x00' in segment
        or '%2e' in low
        or '%2f' in low
        or '%5c' in low
        or '[' in segment
        or ']' in segment
        or any(ord(ch) < 32 for ch in segment)
    ):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSAFE_PATH_SEGMENT'})
    if pattern is not None and not pattern.fullmatch(segment):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSAFE_PATH_SEGMENT'})


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    return False


def _dir_identity(path_or_fd: Path | int) -> tuple[int, int]:
    st = os.fstat(path_or_fd) if isinstance(path_or_fd, int) else os.lstat(path_or_fd)
    if stat.S_ISLNK(st.st_mode) or (getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SYMLINK_ESCAPE_BLOCKED'})
    if not stat.S_ISDIR(st.st_mode):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'DIRECTORY_EXPECTED'})
    return (st.st_dev, st.st_ino)


def _linux_openat2(dir_fd: int, rel_path: str, flags: int, mode: int = 0) -> int | None:
    if _LIBC is None:
        return None
    how = _OpenHow(
        flags=ctypes.c_uint64(flags | getattr(os, 'O_CLOEXEC', 0)),
        mode=ctypes.c_uint64(mode if (flags & os.O_CREAT) else 0),
        resolve=ctypes.c_uint64(
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
        ),
    )
    raw_path = os.fsencode(rel_path)
    ctypes.set_errno(0)
    fd = _LIBC.syscall(
        ctypes.c_long(SYS_OPENAT2),
        ctypes.c_int(dir_fd),
        ctypes.c_char_p(raw_path),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if fd >= 0:
        return int(fd)
    err = ctypes.get_errno()
    if err in (errno.ENOSYS, errno.EPERM):
        return None
    if err in (errno.EXDEV, errno.ELOOP, errno.EACCES, errno.EEXIST, errno.EINVAL, errno.ENOTDIR):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'OPENAT2_ESCAPE_BLOCKED', 'errno': err})
    if err == errno.ENOENT:
        raise FileNotFoundError(rel_path)
    raise OSError(err, os.strerror(err), rel_path)


def _verify_opened_regular_fd(
    fd: int,
    *,
    expected_dev: int,
    expected_uid: int | None = None,
) -> os.stat_result:
    st = os.fstat(fd)
    if getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'REPARSE_POINT_BLOCKED'})
    if not stat.S_ISREG(st.st_mode):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'NON_REGULAR_FILE_BLOCKED'})
    if st.st_nlink != 1:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'HARDLINK_ESCAPE_BLOCKED', 'st_nlink': st.st_nlink})
    if expected_dev != 0 and st.st_dev != 0 and st.st_dev != expected_dev:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
    if hasattr(os, 'geteuid'):
        req_uid = os.geteuid() if expected_uid is None else expected_uid
        if st.st_uid != req_uid:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FILE_UID_MISMATCH'})
    return st


def _parse_png(data: bytes) -> dict:
    if len(data) < 24 or data[12:16] != b'IHDR':
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_PNG_HEADER'})
    ihdr_len = struct.unpack('>I', data[8:12])[0]
    if ihdr_len < 13:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_PNG_HEADER'})
    width, height = struct.unpack('>II', data[16:24])
    if width < 1 or height < 1:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_PNG_HEADER'})
    return {
        'format': 'png',
        'ext': 'png',
        'mime_type': 'image/png',
        'width': int(width),
        'height': int(height),
        'frames': 1,
    }


def _parse_jpeg(data: bytes) -> dict:
    if len(data) < 4 or data[:2] != b'\xff\xd8':
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_JPEG_HEADER'})
    pos = 2
    n = len(data)
    sof_markers = {
        0xC0, 0xC1, 0xC2, 0xC3,
        0xC5, 0xC6, 0xC7,
        0xC9, 0xCA, 0xCB,
        0xCD, 0xCE, 0xCF,
    }
    while pos < n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0x01) or (0xD0 <= marker <= 0xD7):
            continue
        if marker in (0xD9, 0xDA):
            break
        if pos + 2 > n:
            break
        seg_len = struct.unpack('>H', data[pos:pos + 2])[0]
        if seg_len < 2 or pos + seg_len > n:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_JPEG_HEADER'})
        if marker in sof_markers:
            if seg_len < 7:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_JPEG_HEADER'})
            height, width = struct.unpack('>HH', data[pos + 3:pos + 7])
            if width < 1 or height < 1:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_JPEG_HEADER'})
            return {
                'format': 'jpg',
                'ext': 'jpg',
                'mime_type': 'image/jpeg',
                'width': int(width),
                'height': int(height),
                'frames': 1,
            }
        pos += seg_len
    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_JPEG_HEADER'})


def _parse_webp(data: bytes) -> dict:
    if len(data) < 20 or data[:4] != b'RIFF' or data[8:12] != b'WEBP':
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_WEBP_HEADER'})
    pos = 12
    n = len(data)
    while pos + 8 <= n:
        chunk_id = data[pos:pos + 4]
        chunk_len = struct.unpack('<I', data[pos + 4:pos + 8])[0]
        body_start = pos + 8
        body_end = body_start + chunk_len
        if body_end > n:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_WEBP_HEADER'})
        chunk = data[body_start:body_end]
        if chunk_id == b'VP8X' and len(chunk) >= 10:
            width = int.from_bytes(chunk[4:7], 'little') + 1
            height = int.from_bytes(chunk[7:10], 'little') + 1
            return {
                'format': 'webp',
                'ext': 'webp',
                'mime_type': 'image/webp',
                'width': width,
                'height': height,
                'frames': 1,
            }
        if chunk_id == b'VP8 ' and len(chunk) >= 10 and chunk[3:6] == b'\x9d\x01\x2a':
            width = struct.unpack('<H', chunk[6:8])[0] & 0x3FFF
            height = struct.unpack('<H', chunk[8:10])[0] & 0x3FFF
            if width >= 1 and height >= 1:
                return {
                    'format': 'webp',
                    'ext': 'webp',
                    'mime_type': 'image/webp',
                    'width': int(width),
                    'height': int(height),
                    'frames': 1,
                }
        if chunk_id == b'VP8L' and len(chunk) >= 5 and chunk[0] == 0x2F:
            bits = struct.unpack('<I', chunk[1:5])[0]
            width = (bits & 0x3FFF) + 1
            height = ((bits >> 14) & 0x3FFF) + 1
            return {
                'format': 'webp',
                'ext': 'webp',
                'mime_type': 'image/webp',
                'width': int(width),
                'height': int(height),
                'frames': 1,
            }
        pos = body_end + (chunk_len & 1)
    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_WEBP_HEADER'})


def _iter_mp4_boxes(buf: bytes, start: int = 0, end: int | None = None):
    limit = len(buf) if end is None else min(end, len(buf))
    pos = start
    while pos + 8 <= limit:
        size32 = struct.unpack('>I', buf[pos:pos + 4])[0]
        btype = buf[pos + 4:pos + 8]
        hdr = 8
        if size32 == 1:
            if pos + 16 > limit:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
            box_size = struct.unpack('>Q', buf[pos + 8:pos + 16])[0]
            hdr = 16
        elif size32 == 0:
            box_size = limit - pos
        else:
            box_size = size32
        if box_size < hdr or pos + box_size > limit:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
        yield btype, pos + hdr, pos + box_size
        pos += box_size


def _parse_mp4(data: bytes) -> dict:
    has_ftyp = False
    saw_vide_trak = False
    best_width = 0
    best_height = 0
    best_frames = 0

    def _parse_trak(t_start: int, t_end: int):
        nonlocal saw_vide_trak, best_width, best_height, best_frames
        tk_w, tk_h = 0, 0
        stsd_w, stsd_h = 0, 0
        has_stsz = False
        has_stts = False
        frames_stsz = 0
        frames_stts = 0
        handler_type = None

        def _walk(b_start: int, b_end: int, depth: int):
            nonlocal tk_w, tk_h, stsd_w, stsd_h, has_stsz, has_stts, frames_stsz, frames_stts, handler_type
            if depth > 8:
                return
            for btype, c_start, c_end in _iter_mp4_boxes(data, b_start, b_end):
                if btype in (b'moof', b'mvex', b'sidx', b'traf', b'trun'):
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FRAGMENTED_MP4_UNSUPPORTED'})
                payload = data[c_start:c_end]
                if btype == b'tkhd':
                    if len(payload) >= 84:
                        ver = payload[0]
                        if ver == 0 and len(payload) >= 84:
                            w_fp, h_fp = struct.unpack('>II', payload[76:84])
                            tk_w, tk_h = w_fp >> 16, h_fp >> 16
                        elif ver == 1 and len(payload) >= 96:
                            w_fp, h_fp = struct.unpack('>II', payload[88:96])
                            tk_w, tk_h = w_fp >> 16, h_fp >> 16
                elif btype == b'hdlr':
                    if len(payload) >= 12:
                        handler_type = bytes(payload[8:12])
                elif btype == b'stsd':
                    if len(payload) >= 16:
                        entry_count = struct.unpack('>I', payload[4:8])[0]
                        epos = 8
                        for _ in range(min(entry_count, 4)):
                            if epos + 8 > len(payload):
                                break
                            esize = struct.unpack('>I', payload[epos:epos + 4])[0]
                            if esize < 8 or epos + esize > len(payload):
                                break
                            if esize >= 36:
                                cand_w, cand_h = struct.unpack('>HH', payload[epos + 32:epos + 36])
                                if cand_w > 0 and cand_h > 0:
                                    stsd_w, stsd_h = cand_w, cand_h
                            epos += esize
                elif btype == b'stsz':
                    if len(payload) < 12:
                        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
                    has_stsz = True
                    frames_stsz = max(frames_stsz, struct.unpack('>I', payload[8:12])[0])
                elif btype == b'stts':
                    if len(payload) < 8:
                        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
                    cnt = struct.unpack('>I', payload[4:8])[0]
                    if 8 + cnt * 8 > len(payload):
                        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
                    has_stts = True
                    total = 0
                    for i in range(cnt):
                        sc = struct.unpack('>I', payload[8 + i * 8:12 + i * 8])[0]
                        total += sc
                    frames_stts = max(frames_stts, total)
                elif btype in (b'mdia', b'minf', b'stbl'):
                    _walk(c_start, c_end, depth + 1)

        _walk(t_start, t_end, 0)
        if handler_type != b'vide':
            return
        saw_vide_trak = True
        w = stsd_w if stsd_w > 0 else tk_w
        h = stsd_h if stsd_h > 0 else tk_h
        if w < 1 or h < 1:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
        if not has_stsz or not has_stts or frames_stsz != frames_stts or frames_stsz < 1:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNPROVABLE_MP4_FRAME_COUNT'})
        f = frames_stsz
        if w * h >= best_width * best_height:
            best_width, best_height = w, h
        best_frames = max(best_frames, f)

    for btype, c_start, c_end in _iter_mp4_boxes(data):
        if btype == b'ftyp':
            has_ftyp = True
        elif btype in (b'moof', b'mvex', b'sidx'):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FRAGMENTED_MP4_UNSUPPORTED'})
        elif btype == b'moov':
            for sub_type, s_start, s_end in _iter_mp4_boxes(data, c_start, c_end):
                if sub_type in (b'mvex', b'moof', b'sidx'):
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FRAGMENTED_MP4_UNSUPPORTED'})
                if sub_type == b'trak':
                    _parse_trak(s_start, s_end)

    if not has_ftyp or not saw_vide_trak or best_width < 1 or best_height < 1:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CORRUPT_MP4_HEADER'})
    if best_frames < 1:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNPROVABLE_MP4_FRAME_COUNT'})
    return {
        'format': 'mp4',
        'ext': 'mp4',
        'mime_type': 'video/mp4',
        'width': int(best_width),
        'height': int(best_height),
        'frames': int(best_frames),
    }


def parse_media_header(data: bytes, expected_kind: str | None = None) -> dict:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_MEDIA_BYTES'})
    raw = bytes(data)
    if raw.startswith(b'\x89PNG\r\n\x1a\n'):
        info = _parse_png(raw)
    elif raw.startswith(b'\xff\xd8'):
        info = _parse_jpeg(raw)
    elif raw[:4] == b'RIFF' and raw[8:12] == b'WEBP':
        info = _parse_webp(raw)
    elif raw[4:8] == b'ftyp':
        info = _parse_mp4(raw)
    elif raw.startswith(b'\x1a\x45\xdf\xa3'):
        info = {
            'format': 'webm',
            'ext': 'webm',
            'mime_type': 'video/webm',
            'width': 1,
            'height': 1,
            'frames': 1,
        }
    else:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSUPPORTED_MEDIA_FORMAT'})

    info['pixels'] = int(info['width']) * int(info['height'])
    if expected_kind in ('artifact_image', 'artifact_mask'):
        if info['format'] not in ('png', 'jpg', 'webp'):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSUPPORTED_MEDIA_FORMAT', 'expected': expected_kind})
    elif expected_kind == 'artifact_video':
        if info['format'] != 'mp4':
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'UNSUPPORTED_MEDIA_FORMAT', 'expected': expected_kind})
    return info


def enforce_media_envelope(
    info: dict,
    *,
    max_pixels: int,
    max_frames: int | None = None,
) -> None:
    pixels = int(info['width']) * int(info['height'])
    if pixels > max_pixels:
        raise WorkspaceIOError(
            'INVALID_PARAMETERS',
            400,
            details={
                'reason': 'MEDIA_DIMENSIONS_EXCEEDED',
                'width': int(info['width']),
                'height': int(info['height']),
                'pixels': pixels,
                'max_pixels': max_pixels,
            },
        )
    if max_frames is not None and int(info.get('frames', 1)) > max_frames:
        raise WorkspaceIOError(
            'INVALID_PARAMETERS',
            400,
            details={
                'reason': 'MEDIA_DIMENSIONS_EXCEEDED',
                'frames': int(info.get('frames', 1)),
                'max_frames': max_frames,
            },
        )


if os.name == 'nt':
    import msvcrt

    class _WinFileTime(ctypes.Structure):
        _fields_ = [('dwLowDateTime', ctypes.c_uint32), ('dwHighDateTime', ctypes.c_uint32)]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ('dwFileAttributes', ctypes.c_uint32),
            ('ftCreationTime', _WinFileTime),
            ('ftLastAccessTime', _WinFileTime),
            ('ftLastWriteTime', _WinFileTime),
            ('dwVolumeSerialNumber', ctypes.c_uint32),
            ('nFileSizeHigh', ctypes.c_uint32),
            ('nFileSizeLow', ctypes.c_uint32),
            ('nNumberOfLinks', ctypes.c_uint32),
            ('nFileIndexHigh', ctypes.c_uint32),
            ('nFileIndexLow', ctypes.c_uint32),
        ]

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ('CreationTime', ctypes.c_int64),
            ('LastAccessTime', ctypes.c_int64),
            ('LastWriteTime', ctypes.c_int64),
            ('ChangeTime', ctypes.c_int64),
            ('FileAttributes', ctypes.c_uint32),
            ('Reserved', ctypes.c_uint32),
        ]

    _K32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _K32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    _K32.CreateFileW.restype = ctypes.c_void_p
    _K32.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _K32.GetFileInformationByHandle.restype = ctypes.c_int
    _K32.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _K32.SetFileInformationByHandle.restype = ctypes.c_int
    _K32.CloseHandle.argtypes = [ctypes.c_void_p]
    _K32.CloseHandle.restype = ctypes.c_int
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _WIN_OPEN_FLAGS_NOFOLLOW = 0x02200000

    def _win_info_from_handle(handle: int) -> _ByHandleFileInformation:
        info = _ByHandleFileInformation()
        if not _K32.GetFileInformationByHandle(ctypes.c_void_p(handle), ctypes.byref(info)):
            raise OSError(ctypes.get_last_error() or errno.EIO, 'GetFileInformationByHandle failed')
        return info

    def _win_open_pinned_dir(path: Path) -> tuple[int, tuple[int, int]]:
        h = _K32.CreateFileW(str(path), 0x00000080, 0x00000003, None, 3, _WIN_OPEN_FLAGS_NOFOLLOW, None)
        if h is None or h == _INVALID_HANDLE:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
        try:
            info = _win_info_from_handle(h)
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SYMLINK_ESCAPE_BLOCKED'})
            if not (info.dwFileAttributes & 0x10):
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'DIRECTORY_EXPECTED'})
            fid = (int(info.dwVolumeSerialNumber), (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow))
            return int(h), fid
        except BaseException:
            _K32.CloseHandle(ctypes.c_void_p(h))
            raise

    def _win_dispose_handle(handle: int, attrs: int) -> None:
        if (attrs & 0x01) and not (attrs & 0x10) and not (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
            binfo = _FileBasicInfo(0, 0, 0, 0, 0x80, 0)
            _K32.SetFileInformationByHandle(ctypes.c_void_p(handle), 0, ctypes.byref(binfo), ctypes.sizeof(binfo))
        disp = ctypes.c_ubyte(1)
        if not _K32.SetFileInformationByHandle(ctypes.c_void_p(handle), 4, ctypes.byref(disp), ctypes.sizeof(disp)):
            raise OSError(errno.EACCES, 'SetFileInformationByHandle(FileDispositionInfo) failed')

    def _win_unlink_entry_by_handle(
        path: Path,
        *,
        expected_win_id: tuple[int, int] | None = None,
        require_single_link_reg: bool = False,
        race_hook=None,
    ) -> None:
        h = _K32.CreateFileW(str(path), 0x00010180, 0x00000007, None, 3, _WIN_OPEN_FLAGS_NOFOLLOW, None)
        if h is None or h == _INVALID_HANDLE:
            if expected_win_id is not None:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            return
        try:
            info = _win_info_from_handle(h)
            actual_id = (int(info.dwVolumeSerialNumber), (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow))
            if expected_win_id is not None and actual_id != expected_win_id:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            if require_single_link_reg:
                if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) or (info.dwFileAttributes & 0x10) or info.nNumberOfLinks != 1:
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            if callable(race_hook):
                race_hook('before_actual_unlink', path)
            _win_dispose_handle(h, int(info.dwFileAttributes))
        finally:
            _K32.CloseHandle(ctypes.c_void_p(h))


def _ensure_safe_subdir(parent_path: Path, segment: str, *, expected_dev: int, mode: int = 0o700) -> tuple[Path, tuple[int, int]]:
    _reject_unsafe_segment(segment)
    parent_id = _dir_identity(parent_path)
    child = parent_path / segment
    if _is_reparse_or_symlink(child):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SYMLINK_ESCAPE_BLOCKED'})
    if not child.exists():
        os.mkdir(child, mode)
    child_id = _dir_identity(child)
    if expected_dev != 0 and child_id[0] != 0 and child_id[0] != expected_dev:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
    if _dir_identity(parent_path) != parent_id:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
    return child, child_id


def materialize_task_input_bytes(
    workspace_root: str | Path,
    *,
    task_id: str,
    slot_index: int,
    data: bytes,
    expected_kind: str | None = 'artifact_image',
    explicit_filename: str | None = None,
    race_hook=None,
) -> dict:
    _reject_unsafe_segment(task_id, SAFE_TASK_ID_RE)
    if type(slot_index) is not int or not (0 <= slot_index <= 99):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'INVALID_SLOT_INDEX'})
    header = parse_media_header(data, expected_kind=expected_kind)
    ext = header['ext']

    if explicit_filename is not None:
        _reject_unsafe_segment(explicit_filename, SAFE_INPUT_FILENAME_RE)
        fname = explicit_filename
    else:
        fname = f'in_{slot_index}_{secrets.token_hex(6)}.{ext}'
        _reject_unsafe_segment(fname, SAFE_INPUT_FILENAME_RE)

    root = Path(workspace_root)
    if not root.exists():
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'WORKSPACE_ROOT_MISSING'})
    root_dev, _ = _dir_identity(root)

    inputs_dir, inputs_id = _ensure_safe_subdir(root, 'inputs', expected_dev=root_dev)
    task_dir, task_dir_id = _ensure_safe_subdir(inputs_dir, task_id, expected_dev=root_dev)

    if callable(race_hook):
        race_hook('before_open_input', task_dir)

    if _dir_identity(inputs_dir) != inputs_id or _dir_identity(task_dir) != task_dir_id:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

    target_path = task_dir / fname
    if _is_reparse_or_symlink(target_path):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SYMLINK_ESCAPE_BLOCKED'})

    open_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, 'O_NOFOLLOW'):
        open_flags |= os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        open_flags |= os.O_CLOEXEC
    if hasattr(os, 'O_BINARY'):
        open_flags |= os.O_BINARY

    fd = None
    dir_fd = None
    win_pin_dir_h = None
    created_file_id: tuple[int, int] | None = None
    created_win_id: tuple[int, int] | None = None
    try:
        if os.name != 'nt' and hasattr(os, 'O_DIRECTORY'):
            dir_open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
            root_fd = os.open(str(root), dir_open_flags)
            try:
                dir_fd = os.open(f'inputs/{task_id}', dir_open_flags, dir_fd=root_fd)
                if _dir_identity(dir_fd) != task_dir_id:
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
                rel_from_root = f'inputs/{task_id}/{fname}'
                fd = _linux_openat2(root_fd, rel_from_root, open_flags, 0o400)
                if fd is None:
                    fd = os.open(fname, open_flags, 0o400, dir_fd=dir_fd)
            finally:
                os.close(root_fd)
        else:
            win_pin_dir_h, _ = _win_open_pinned_dir(task_dir)
            if _dir_identity(task_dir) != task_dir_id:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            try:
                fd = os.open(str(target_path), open_flags, 0o600)
            except FileExistsError as exc:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'INPUT_TARGET_EXISTS'}) from exc

        st_created = _verify_opened_regular_fd(fd, expected_dev=root_dev)
        created_file_id = (int(st_created.st_dev), int(st_created.st_ino))
        if os.name == 'nt':
            winfo = _win_info_from_handle(msvcrt.get_osfhandle(fd))
            created_win_id = (int(winfo.dwVolumeSerialNumber), (int(winfo.nFileIndexHigh) << 32) | int(winfo.nFileIndexLow))
        if callable(race_hook):
            race_hook('after_open_before_verify_parent', task_dir)
        if _dir_identity(task_dir) != task_dir_id:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

        raw_bytes = bytes(data)
        view = memoryview(raw_bytes)
        written = 0
        while written < len(raw_bytes):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise OSError(errno.EIO, 'short write')
            written += n
        if os.name != 'nt':
            os.fchmod(fd, 0o400)
    except WorkspaceIOError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            fd = None
        if created_file_id is not None:
            if os.name != 'nt' and dir_fd is not None:
                _posix_rollback_unlink_created_entry(
                    dir_fd,
                    fname,
                    created_file_id,
                    target_path=target_path,
                    race_hook=race_hook,
                )
            elif os.name == 'nt' and created_win_id is not None:
                _win_unlink_entry_by_handle(
                    target_path,
                    expected_win_id=created_win_id,
                    require_single_link_reg=True,
                    race_hook=race_hook,
                )
        raise
    except FileExistsError as exc:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'INPUT_TARGET_EXISTS'}) from exc
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            fd = None
        if created_file_id is not None:
            try:
                if os.name != 'nt' and dir_fd is not None:
                    _posix_rollback_unlink_created_entry(
                        dir_fd,
                        fname,
                        created_file_id,
                        target_path=target_path,
                        race_hook=race_hook,
                    )
                elif os.name == 'nt' and created_win_id is not None:
                    _win_unlink_entry_by_handle(target_path, expected_win_id=created_win_id, require_single_link_reg=True)
            except (OSError, WorkspaceIOError):
                pass
        if exc.errno in (errno.ELOOP, errno.EXDEV, errno.ENOTDIR, errno.EEXIST, errno.EINVAL):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FILESYSTEM_ESCAPE_BLOCKED', 'errno': exc.errno}) from exc
        raise
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass
        if win_pin_dir_h is not None:
            _K32.CloseHandle(ctypes.c_void_p(win_pin_dir_h))

    return {
        'relative_path': f'{task_id}/{fname}',
        'filename': fname,
        'sha256': hashlib.sha256(data).hexdigest(),
        'size_bytes': len(data),
        'media_info': header,
    }


def collect_task_output_files(
    workspace_root: str | Path,
    *,
    task_id: str,
    expected_node_ids: list[str] | None = None,
    race_hook=None,
) -> list[dict]:
    _reject_unsafe_segment(task_id, SAFE_TASK_ID_RE)
    root = Path(workspace_root)
    root_dev, _ = _dir_identity(root)

    outputs_dir = root / 'outputs'
    vf_dir = outputs_dir / 'vf'
    task_out_dir = vf_dir / task_id
    if not task_out_dir.exists():
        raise WorkspaceIOError('OUTPUT_MISSING', 502, details={'reason': 'TASK_OUTPUT_DIR_MISSING'})

    outputs_id = _dir_identity(outputs_dir)
    vf_id = _dir_identity(vf_dir)
    task_out_id = _dir_identity(task_out_dir)

    entries = sorted(os.listdir(task_out_dir))
    if callable(race_hook):
        race_hook('after_list_before_open', task_out_dir)

    if (
        _dir_identity(outputs_dir) != outputs_id
        or _dir_identity(vf_dir) != vf_id
        or _dir_identity(task_out_dir) != task_out_id
    ):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

    collected: list[dict] = []
    for fname in entries:
        _reject_unsafe_segment(fname, SAFE_OUTPUT_FILENAME_RE)
        m_node = re.match(r'^out_([1-9][0-9]{0,5})_', fname)
        node_id = m_node.group(1) if m_node else '7'
        fpath = task_out_dir / fname
        if _is_reparse_or_symlink(fpath):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SYMLINK_ESCAPE_BLOCKED'})

        open_flags = os.O_RDONLY
        if hasattr(os, 'O_NOFOLLOW'):
            open_flags |= os.O_NOFOLLOW
        if hasattr(os, 'O_CLOEXEC'):
            open_flags |= os.O_CLOEXEC
        if hasattr(os, 'O_BINARY'):
            open_flags |= os.O_BINARY

        fd = None
        try:
            if os.name != 'nt' and hasattr(os, 'O_DIRECTORY'):
                dir_open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
                root_fd = os.open(str(root), dir_open_flags)
                try:
                    rel_from_root = f'outputs/vf/{task_id}/{fname}'
                    fd = _linux_openat2(root_fd, rel_from_root, open_flags, 0)
                    if fd is None:
                        t_fd = os.open(f'outputs/vf/{task_id}', dir_open_flags, dir_fd=root_fd)
                        try:
                            if _dir_identity(t_fd) != task_out_id:
                                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
                            fd = os.open(fname, open_flags, dir_fd=t_fd)
                        finally:
                            os.close(t_fd)
                finally:
                    os.close(root_fd)
            else:
                fd = os.open(str(fpath), open_flags)

            st = _verify_opened_regular_fd(fd, expected_dev=root_dev)
            if _dir_identity(task_out_dir) != task_out_id:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            if st.st_size <= 0 or st.st_size > (512 << 20):
                raise WorkspaceIOError('OUTPUT_INVALID', 502, details={'reason': 'INVALID_OUTPUT_FILE_SIZE'})

            chunks: list[bytes] = []
            remaining = st.st_size
            while remaining > 0:
                buf = os.read(fd, min(65536, remaining))
                if not buf:
                    break
                chunks.append(buf)
                remaining -= len(buf)
            raw = b''.join(chunks)
            if len(raw) != st.st_size:
                raise WorkspaceIOError('OUTPUT_INVALID', 502, details={'reason': 'SHORT_OUTPUT_READ'})
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EXDEV, errno.ENOTDIR, errno.EINVAL):
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'FILESYSTEM_ESCAPE_BLOCKED', 'errno': exc.errno}) from exc
            raise
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        media_info = parse_media_header(raw)
        collected.append({
            'node_id': node_id,
            'filename': fname,
            'mime_type': media_info['mime_type'],
            'size_bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'data': raw,
            'media_info': media_info,
        })

    if expected_node_ids:
        found_nodes = {item['node_id'] for item in collected}
        missing = [nid for nid in expected_node_ids if nid not in found_nodes]
        if missing:
            raise WorkspaceIOError('OUTPUT_MISSING', 502, details={'missing_output_node_ids': missing})
    elif not collected:
        raise WorkspaceIOError('OUTPUT_MISSING', 502, details={'reason': 'NO_OUTPUT_FILES'})

    return collected


def _posix_rename_noreplace(
    src_name: str,
    dst_name: str,
    *,
    src_dir_fd: int,
    dst_dir_fd: int,
    syscall_ops=os,
) -> None:
    """Atomically rename `(src_dir_fd, src_name) -> (dst_dir_fd, dst_name)` with `RENAME_NOREPLACE` semantics (never overwrites)."""
    if hasattr(syscall_ops, 'rename_noreplace'):
        syscall_ops.rename_noreplace(src_name, dst_name, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        return
    if syscall_ops is os and _LIBC is not None and sys.platform.startswith('linux'):
        arch = os.uname().machine
        sys_nr = 316 if arch == 'x86_64' else (276 if arch == 'aarch64' else None)
        if sys_nr is not None:
            ctypes.set_errno(0)
            rc = _LIBC.syscall(
                ctypes.c_long(sys_nr),
                ctypes.c_int(src_dir_fd),
                ctypes.c_char_p(os.fsencode(src_name)),
                ctypes.c_int(dst_dir_fd),
                ctypes.c_char_p(os.fsencode(dst_name)),
                ctypes.c_uint(1),  # RENAME_NOREPLACE = (1 << 0)
            )
            if rc < 0:
                err = ctypes.get_errno() or errno.EIO
                if err in (errno.ENOSYS, errno.EINVAL):
                    raise NotImplementedError('renameat2 RENAME_NOREPLACE unsupported')
                raise OSError(err, os.strerror(err))
            return
    raise NotImplementedError('rename_noreplace unavailable')


def _posix_rollback_unlink_created_entry(
    dir_fd: int,
    fname: str,
    created_file_id: tuple[int, int],
    *,
    target_path: Path,
    race_hook=None,
    syscall_ops=os,
) -> None:
    """Atomically isolate `fname` in a private 0o700 subdir under `dir_fd`, verify `(st_dev, st_ino)` inside `q_fd`, and unlink ONLY if identical."""
    try:
        st_pre = syscall_ops.stat(fname, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'}) from None
    if (
        not stat.S_ISREG(st_pre.st_mode)
        or st_pre.st_nlink != 1
        or (int(st_pre.st_dev), int(st_pre.st_ino)) != created_file_id
    ):
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

    if callable(race_hook):
        race_hook('before_actual_unlink', target_path)
        race_hook('post_stat_pre_unlink_hook', target_path)

    q_name = f'.q_{secrets.token_hex(8)}'
    dir_open_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    syscall_ops.mkdir(q_name, 0o700, dir_fd=dir_fd)
    q_fd = None
    moved = False
    try:
        q_fd = syscall_ops.open(q_name, dir_open_flags, dir_fd=dir_fd)
        st_q = syscall_ops.fstat(q_fd)
        if not stat.S_ISDIR(st_q.st_mode) or (created_file_id[0] != 0 and int(st_q.st_dev) != created_file_id[0]):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
        try:
            syscall_ops.rename(fname, 'entry', src_dir_fd=dir_fd, dst_dir_fd=q_fd)
            moved = True
        except FileNotFoundError:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'}) from None

        st_moved = syscall_ops.stat('entry', dir_fd=q_fd, follow_symlinks=False)
        is_ours = (
            stat.S_ISREG(st_moved.st_mode)
            and st_moved.st_nlink == 1
            and (int(st_moved.st_dev), int(st_moved.st_ino)) == created_file_id
        )
        if not is_ours:
            # Never unlink a swapped external entry and NEVER call plain overwriting rename!
            # Restore only via atomic non-overwriting `RENAME_NOREPLACE` or kernel-atomic `linkat`;
            # if unsupported or `fname` is concurrently occupied (`EEXIST`), preserve `.q_<hex>/entry` intact.
            try:
                _posix_rename_noreplace('entry', fname, src_dir_fd=q_fd, dst_dir_fd=dir_fd, syscall_ops=syscall_ops)
                moved = False
            except (NotImplementedError, AttributeError):
                try:
                    syscall_ops.link('entry', fname, src_dir_fd=q_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
                    syscall_ops.unlink('entry', dir_fd=q_fd)
                    moved = False
                except (OSError, AttributeError, NotImplementedError):
                    pass
            except OSError:
                pass
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

        syscall_ops.unlink('entry', dir_fd=q_fd)
        moved = False
    finally:
        if q_fd is not None:
            try:
                syscall_ops.close(q_fd)
            except OSError:
                pass
        if not moved:
            try:
                syscall_ops.rmdir(q_name, dir_fd=dir_fd)
            except OSError:
                pass


def _scrub_posix_entry_at(
    parent_fd: int,
    entry_name: str,
    *,
    expected_dev: int,
    race_hook=None,
    debug_path: Path,
    depth: int = 0,
) -> int:
    if depth > 16:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SCRUB_DEPTH_EXCEEDED'})
    _reject_unsafe_segment(entry_name)
    st_c = os.stat(entry_name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(st_c.st_mode):
        if callable(race_hook):
            race_hook('before_actual_unlink', debug_path)
        os.unlink(entry_name, dir_fd=parent_fd)
        return 1
    if expected_dev != 0 and st_c.st_dev != 0 and st_c.st_dev != expected_dev:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
    dir_open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    c_fd = os.open(entry_name, dir_open_flags, dir_fd=parent_fd)
    removed = 0
    try:
        st_open = os.fstat(c_fd)
        if not stat.S_ISDIR(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (st_c.st_dev, st_c.st_ino):
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
        dup_fd = os.dup(c_fd)
        try:
            with os.scandir(dup_fd) as it:
                sub_names = [e.name for e in it]
        finally:
            try:
                os.close(dup_fd)
            except OSError:
                pass
        if callable(race_hook):
            race_hook('after_enum_before_scrub', debug_path)
        for sub_name in sub_names:
            removed += _scrub_posix_entry_at(
                c_fd,
                sub_name,
                expected_dev=expected_dev,
                race_hook=race_hook,
                debug_path=debug_path / sub_name,
                depth=depth + 1,
            )
    finally:
        os.close(c_fd)
    if callable(race_hook):
        race_hook('before_actual_unlink', debug_path)
    os.rmdir(entry_name, dir_fd=parent_fd)
    return removed + 1


def _scrub_nt_dir_pinned(
    dir_path: Path,
    *,
    expected_id: tuple[int, int],
    expected_dev: int,
    race_hook=None,
    depth: int = 0,
) -> int:
    if depth > 16:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'SCRUB_DEPTH_EXCEEDED'})
    names = list(os.listdir(dir_path))
    if callable(race_hook):
        race_hook('after_enum_before_scrub', dir_path)
    if _dir_identity(dir_path) != expected_id:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
    pin_h, _ = _win_open_pinned_dir(dir_path)
    removed = 0
    try:
        if _dir_identity(dir_path) != expected_id:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
        for child_name in names:
            _reject_unsafe_segment(child_name)
            cpath = dir_path / child_name
            if _is_reparse_or_symlink(cpath):
                _win_unlink_entry_by_handle(cpath, race_hook=race_hook)
                removed += 1
            elif cpath.is_dir():
                sub_id = _dir_identity(cpath)
                if expected_dev != 0 and sub_id[0] != 0 and sub_id[0] != expected_dev:
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
                removed += _scrub_nt_dir_pinned(
                    cpath,
                    expected_id=sub_id,
                    expected_dev=expected_dev,
                    race_hook=race_hook,
                    depth=depth + 1,
                )
            else:
                _win_unlink_entry_by_handle(cpath, race_hook=race_hook)
                removed += 1
    finally:
        _K32.CloseHandle(ctypes.c_void_p(pin_h))
    _win_unlink_entry_by_handle(dir_path, race_hook=race_hook)
    return removed + 1


def _safe_scrub_one_dir(parent_dir: Path, segment: str, *, expected_dev: int, race_hook=None) -> int:
    _reject_unsafe_segment(segment, SAFE_TASK_ID_RE)
    if not parent_dir.exists():
        return 0
    parent_id = _dir_identity(parent_dir)
    target = parent_dir / segment
    if not target.exists() and not _is_reparse_or_symlink(target):
        return 0

    if os.name != 'nt' and hasattr(os, 'O_DIRECTORY'):
        if _is_reparse_or_symlink(target):
            dir_open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
            p_fd = os.open(str(parent_dir), dir_open_flags)
            try:
                if _dir_identity(p_fd) != parent_id:
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
                if callable(race_hook):
                    race_hook('before_actual_unlink', target)
                os.unlink(segment, dir_fd=p_fd)
                return 1
            finally:
                os.close(p_fd)

        target_id = _dir_identity(target)
        if expected_dev != 0 and target_id[0] != 0 and target_id[0] != expected_dev:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
        names = list(os.listdir(target))
        if callable(race_hook):
            race_hook('after_enum_before_scrub', target)
        if _dir_identity(parent_dir) != parent_id or _dir_identity(target) != target_id:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})

        dir_open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        p_fd = os.open(str(parent_dir), dir_open_flags)
        removed = 0
        try:
            if _dir_identity(p_fd) != parent_id:
                raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
            t_fd = os.open(segment, dir_open_flags, dir_fd=p_fd)
            try:
                if _dir_identity(t_fd) != target_id:
                    raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
                for child_name in names:
                    removed += _scrub_posix_entry_at(
                        t_fd,
                        child_name,
                        expected_dev=expected_dev,
                        race_hook=race_hook,
                        debug_path=target / child_name,
                        depth=1,
                    )
            finally:
                os.close(t_fd)
            if callable(race_hook):
                race_hook('before_actual_unlink', target)
            os.rmdir(segment, dir_fd=p_fd)
            removed += 1
        finally:
            os.close(p_fd)
        return removed

    p_pin_h, _ = _win_open_pinned_dir(parent_dir)
    try:
        if _dir_identity(parent_dir) != parent_id:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'PARENT_DIR_SWAP_DETECTED'})
        if _is_reparse_or_symlink(target):
            _win_unlink_entry_by_handle(target, race_hook=race_hook)
            return 1
        target_id = _dir_identity(target)
        if expected_dev != 0 and target_id[0] != 0 and target_id[0] != expected_dev:
            raise WorkspaceIOError('INVALID_PARAMETERS', 400, details={'reason': 'CROSS_DEVICE_ESCAPE_BLOCKED'})
        return _scrub_nt_dir_pinned(
            target,
            expected_id=target_id,
            expected_dev=expected_dev,
            race_hook=race_hook,
            depth=0,
        )
    finally:
        _K32.CloseHandle(ctypes.c_void_p(p_pin_h))


def scrub_task_workspace_dirs(
    workspace_root: str | Path,
    *,
    task_id: str,
    race_hook=None,
) -> dict:
    _reject_unsafe_segment(task_id, SAFE_TASK_ID_RE)
    root = Path(workspace_root)
    if not root.exists():
        return {'scrubbed': True, 'removed_entries': 0}
    root_dev, _ = _dir_identity(root)

    removed = 0
    inputs_parent = root / 'inputs'
    if inputs_parent.exists():
        removed += _safe_scrub_one_dir(inputs_parent, task_id, expected_dev=root_dev, race_hook=race_hook)

    outputs_vf_parent = root / 'outputs' / 'vf'
    if outputs_vf_parent.exists():
        _dir_identity(root / 'outputs')
        removed += _safe_scrub_one_dir(outputs_vf_parent, task_id, expected_dev=root_dev, race_hook=race_hook)

    temp_parent = root / 'temp'
    if temp_parent.exists():
        removed += _safe_scrub_one_dir(temp_parent, task_id, expected_dev=root_dev, race_hook=race_hook)

    return {'scrubbed': True, 'removed_entries': removed}


def encode_b64_payload(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def decode_b64_payload(b64_str: str) -> bytes:
    if not isinstance(b64_str, str) or not b64_str:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400)
    try:
        return base64.b64decode(b64_str.encode('ascii'), validate=True)
    except Exception as exc:
        raise WorkspaceIOError('INVALID_PARAMETERS', 400) from exc
