"""Pytest configuration for verdantflare-app-comfyui."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _enable_gpu_profiles_for_p1b_residency_suite(request, monkeypatch):
    # Preserve P1b `supervisor_residency_test.py` (untouched parallel slice) which exercises
    # `gpu-shared` instance lifecycle assuming Step-6 GPU profile enablement, while keeping
    # default fail-closed `COMFYUI_ENABLE_GPU_PROFILES=0` across the rest of the suite.
    if request.node.fspath and request.node.fspath.basename == 'supervisor_residency_test.py':
        monkeypatch.setenv('COMFYUI_ENABLE_GPU_PROFILES', '1')
