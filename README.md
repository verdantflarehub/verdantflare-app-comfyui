# VerdantFlare App ComfyUI

ComfyUI 的 Studio 嵌入与领域适配项目。当前交付本地接入、内部 HTTP/MCP 开发服务与任务执行适配；尚无生产发布、GPU 运行或市场安装验收。

## 1. 当前内容

- `upstream.lock.json`：经实际下载核对的上游及前端制品锁。
- `frontend/`：隔离 iframe 的存储兼容、HTTP/事件桥接和宿主白名单。
- `app/task_store.py`：SQLite 持久任务台账、幂等受理、队列上限、唯一派发、输出描述与取消屏障。
- `app/editing.py`：单写编辑租约、固定基础修订、本地草稿版本检查与幂等更新。
- `app/server.py`、`app/service.py`：共享应用方法的内部 HTTP/MCP 入口，服务凭据、真实主体和实例绑定检查。
- `app/protocol.py`：固定内部地址、禁止重定向、限长 JSON 传输及实时 Project 读写权限预检。
- `app/workflow.py`、`app/execution.py`：固定原生 SDXL 图结构与模型文件校验、原 prompt_id 对账及精确取消；执行器仅供显式驱动验证。
- `app/generated_tools.json`：设计仓库机器定义的生成副本，不能独立修改。
- `worker/`：第一方启动器及原生执行门禁，绑定进程 boot_id、内部凭据与精确操作路径。
- `scripts/prepare_frontend.py`：校验官方前端包，生成独立嵌入入口，保留官方静态字节。
- `tests/`：网络边界与消息恢复测试。

## 2. 本地准备与检查

需要 Python 3.12+ 与 Node.js 22+；当前工具不依赖 npm 第三方包。Python 服务使用锁定的 JSON Schema 验证依赖，建议在独立虚拟环境安装。

```sh
python -m pip install -r requirements-dev.txt
python scripts/prepare_frontend.py --wheel /path/to/comfyui_frontend_package-1.48.7-py3-none-any.whl
npm test
python -m unittest discover -s tests -p '*_test.py' -v
python scripts/sync_contract.py --source ../docs/design/app/comfyui/mcp-tools.dev.json --check
```

省略 `--wheel` 时从锁定的官方地址下载并校验。输出写入忽略的 `build/frontend/`，不把官方构建产物、模型或生成内容加入源码库。

仅运行 App 控制服务可安装 `requirements.txt`；完整本地测试使用 `requirements-dev.txt` 中锁定的 aiohttp 及传递依赖。它不是完整 ComfyUI/CUDA 运行环境锁。

本地研究宿主使用测试响应，不能作为 ComfyUI runtime、Studio 鉴权或生成验收证据。HTTP/WS 桥接只承载获准路由；生产接入还需要服务端逐主体、实例与项目鉴权。当前默认禁止生成、全局中断和在线依赖安装。`vf-embed.html` 应在实例目录的 `/` 路由返回，使上游资源和 API 基路径一致；不要把 HTML 文件名当作应用基路径。

桥接采用独立 MessagePort 与加载代次；页面切换或撤权时宿主必须调用 `dispose()`。适配器不是网络隔离的单独保证，部署时还须设置 iframe sandbox、CSP、静态资源 CORS 和服务端白名单，具体约束见设计仓库。

任务台账的状态推进方法只供内部执行器调用。内容完成仍须由后续可信 Artifact 适配器确认；本轮执行成功最多到 collecting。worker 代次变化会冻结派发，尚无自动解除排空或跨代次恢复接口；不确定任务不会自动重跑。输出描述不等于输出字节已保存。

## 3. 内部开发服务启动

从环境读取三个不同的服务凭据：`COMFYUI_APP_TOKEN`、`COMFYUI_PROJECT_TOKEN`、`COMFYUI_AUTHORITY_TOKEN`。每项至少 32 个 ASCII 字符、不含空白；不要在配置、命令行参数或 Git 中保存值。Project 地址必须是受控内部服务，不能使用外部用户 Bearer 替代内部凭据。

配置文件保存到忽略的 `data/config.json`，字段为 `database`、`alias`、`instance_id`、`organization_id`、`user_id`、`project_origin` 和可选 `port`。主体及实例采用实际 UUIDv7；别名如 comfyuiA。默认不配置模型，能力查询会显示生成依赖未就绪。配置及实例主体是启动时绑定，修改归属须受控重启；项目成员权限在每次操作与派发前实时复验。

```sh
python -m app.server --config data/config.json
```

开发服务只监听本机回环地址。不会启动 ComfyUI、下载模型或运行派发线程；入队不等于已开始生成。真实部署还须集成 worker 启动器、单进程约束、Studio 路由及网络隔离。不要直接对外暴露本服务或原生 8188。

编辑工具包含 session.open/renew/close 与 workflow.get/update；续租和草稿写入经过实时项目授权。租期 120 秒，更新需要 expected_version 和重试键。相同主体的另一窗口也需要独立会话，不能同时持有第二个编辑租约。本地草稿不会自动提交为 Project 修订。

机器定义更新先修改设计仓库，再运行 `scripts/sync_contract.py --source ...` 生成副本；`--check` 校验来源摘要及生成内容。测试中的 Project 与原生 ComfyUI 是本地 HTTP 后端，模型为无实际模型内容的测试字节；不作为真实数据库授权、模型或 GPU 验收。

## 4. 第一方 worker 启动器

在已准备好完整依赖的锁定 ComfyUI 源码环境中，使用 `python -m worker.launch --comfy-root /path/to/ComfyUI -- <上游参数>`。运行前由受控环境提供 `COMFYUI_INSTANCE_ID` 和独立的 `COMFYUI_WORKER_TOKEN`，不把值写到命令行或仓库。启动器保持上游 main 的初始化顺序，在 PromptServer 创建时安装门禁；缺少配置或安装失败即停止启动。

启动器强制关闭第三方 custom nodes 和外部 API 节点，拒绝启用节点白名单及在线 manager。第一方门禁通过启动器安装，不依赖 custom node 加载。原生路由当前只开放任务执行器需要的窄范围 API；编辑元数据、WS、上传与预览仍待受控接入。

App 的 NativeClient 必须提供内部 worker 凭据。ExecutionAdapter 每次驱动先验证实例和进程 boot_id，再将 boot_id 绑定到所有原生读取与写入；启动标识变化使台账提升代次并冻结旧任务和会话。未知旧在途任务不自动接管，缺少原生任务记录不自动重提。此切片尚无跨代次解冻流程或持久接收协议。

本地验证包含实际 aiohttp 门禁、NativeClient HTTP 请求与启动器子进程；上游 main/PromptServer 初始化顺序已按锁定源码核对。测试后端和最小启动 fixture 不代表完整 ComfyUI/CUDA/GPU 已运行，镜像入口也尚未集成。

## 5. 文档依据

- [ComfyUI 设计与验收](https://github.com/verdantflarehub/verdantflare-design/blob/dev/docs/design/app/comfyui/README.md)。
- [ComfyUI 交付计划](https://github.com/verdantflarehub/verdantflare-design/blob/dev/plan/2026.10.comfyui-dev.plan.md)。
- [上游与分发说明](UPSTREAM.md)。

产品/API 和部署事实源由设计仓库维护。本项目仅维护源码、上游记录、构建与本地检查；后续分支仅使用 dev/release/main。
