"""Dedicated S6 fault-injection ComfyUI PromptServer shim (test-only image)."""
from aiohttp import web


class _DummyPromptQueue:
    def get_current_queue(self):
        return ([], [])


class PromptServer:
    instance = None

    def __init__(self, loop=None):
        self.loop = loop
        self.app = web.Application()
        self.prompt_queue = _DummyPromptQueue()
        PromptServer.instance = self
        self.app.router.add_get('/', self._root)
        self.app.router.add_get('/system_stats', self._system_stats)
        self.app.router.add_get('/queue', self._queue)
        self.app.router.add_post('/interrupt', self._ok)
        self.app.router.add_post('/free', self._ok)
        self.app.router.add_get('/s6_status', self._s6_status)

    async def _root(self, _request):
        return web.Response(text='comfyui-s6-fault-stub', content_type='text/plain')

    async def _system_stats(self, _request):
        return web.json_response({
            'system': {'os': 'linux', 'comfyui_version': 's6-fault-stub'},
            'devices': [{'name': 'cuda:0', 'type': 'cuda'}],
        })

    async def _queue(self, _request):
        return web.json_response({'queue_running': [], 'queue_pending': []})

    async def _ok(self, _request):
        return web.json_response({'ok': True})

    async def _s6_status(self, request):
        state = request.app.get('s6_state', {})
        return web.json_response({'ok': True, **state})
