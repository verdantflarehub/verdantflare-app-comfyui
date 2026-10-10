# VerdantFlare App ComfyUI

ComfyUI 的 Studio 嵌入与领域适配项目。当前交付本地接入验证基础；没有生产服务、MCP 发布、GPU 运行或市场安装能力。

## 1. 当前内容

- `upstream.lock.json`：经实际下载核对的上游及前端制品锁。
- `frontend/`：隔离 iframe 的存储兼容、HTTP/事件桥接和宿主白名单。
- `app/task_store.py`：SQLite 持久任务台账、幂等受理、唯一派发、取消与重启保护；尚未绑定实际鉴权或执行器。
- `scripts/prepare_frontend.py`：校验官方前端包，生成独立嵌入入口，保留官方静态字节。
- `tests/`：网络边界与消息恢复测试。

## 2. 本地准备与检查

需要 Python 3.12+ 与 Node.js 22+；当前工具不依赖 npm 第三方包。

```sh
python scripts/prepare_frontend.py --wheel /path/to/comfyui_frontend_package-1.48.7-py3-none-any.whl
npm test
python -m unittest discover -s tests -p '*_test.py' -v
```

省略 `--wheel` 时从锁定的官方地址下载并校验。输出写入忽略的 `build/frontend/`，不把官方构建产物、模型或生成内容加入源码库。

本地研究宿主使用测试响应，不能作为 ComfyUI runtime、Studio 鉴权或生成验收证据。HTTP/WS 桥接只承载获准路由；生产接入还需要服务端逐主体、实例与项目鉴权。当前默认禁止生成、全局中断和在线依赖安装。`vf-embed.html` 应在实例目录的 `/` 路由返回，使上游资源和 API 基路径一致；不要把 HTML 文件名当作应用基路径。

桥接采用独立 MessagePort 与加载代次；页面切换或撤权时宿主必须调用 `dispose()`。适配器不是网络隔离的单独保证，部署时还须设置 iframe sandbox、CSP、静态资源 CORS 和服务端白名单，具体约束见设计仓库。

任务台账是内部模块：调用者必须已经通过实时实例与项目鉴权；`mark_validated` 只能在执行适配器完成工作流/依赖校验后调用。内容完成由可信 Artifact 适配器确认。worker 代次变化会冻结派发并留下对账状态，尚无自动解除排空或跨代次恢复接口；不确定任务不会自动重跑。

## 3. 文档依据

- [ComfyUI 设计与验收](https://github.com/verdantflarehub/verdantflare-design/blob/dev/docs/design/app/comfyui/README.md)。
- [ComfyUI 交付计划](https://github.com/verdantflarehub/verdantflare-design/blob/dev/plan/2026.10.comfyui-dev.plan.md)。
- [上游与分发说明](UPSTREAM.md)。

产品/API 和部署事实源由设计仓库维护。本项目仅维护源码、上游记录、构建与本地检查；后续分支仅使用 dev/release/main。
