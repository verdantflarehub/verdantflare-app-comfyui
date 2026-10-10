# VerdantFlare App ComfyUI

ComfyUI 的 Studio 嵌入与领域适配项目。历史本地基础编辑器联调已覆盖 Studio/Core 实际身份、App 与官方 CPU runtime；当前 CPU 依赖锁已在 5090 dev 解析，待 CI 构建和目标环境运行验收。尚无生产发布、GPU 运行或市场安装验收。

## 1. 当前内容

- `upstream.lock.json`：经实际下载核对的上游及前端制品锁。
- `frontend/`：隔离 iframe 的存储兼容、HTTP/事件桥接和宿主白名单。
- `app/task_store.py`：SQLite 持久任务台账、幂等受理、队列上限、唯一派发、输出描述与取消屏障。
- `app/editing.py`：单写编辑租约、固定基础修订、本地草稿版本检查与幂等更新。
- `app/instances.py`：不依赖 Project 的授权实例目录，校验 worker 身份与私有资源绑定；缺少可信采样时不填造用量。
- `app/editor.py`、`app/editor_transport.py`：独立于 Project 的基础编辑器、单写租约、版本草稿和设置/JSON 文件；固定静态制品及限时 WS 状态读取。
- `app/server.py`、`app/service.py`：共享应用方法的内部 HTTP/MCP 入口，服务凭据、真实主体和实例绑定检查。
- `app/protocol.py`：固定内部地址、禁止重定向、限长 JSON 传输及实时 Project 读写权限预检。
- `app/workflow.py`、`app/execution.py`：固定原生 SDXL 图结构与模型文件校验、原 prompt_id 对账及精确取消；执行器仅供显式驱动验证。
- `app/generated_tools.json`：设计仓库机器定义的生成副本，不能独立修改。
- `worker/`：第一方启动器及原生执行门禁，绑定进程 boot_id、内部凭据与精确操作路径。
- `scripts/prepare_frontend.py`：校验官方前端包，生成独立嵌入入口；只应用锁定的初始化单点补丁，核验输入/输出哈希。
- `scripts/prepare_runtime.py`：核验官方源码 ZIP 大小/哈希并安全提取，不覆盖已有源码目录。
- `Dockerfile`、`Dockerfile.worker`：控制服务与 worker 分离构建，生产依赖使用哈希锁；本轮 release CI 构建 App 与 CPU worker，GPU 配置留到生成阶段。
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

镜像由 GitHub Actions 构建；工作区禁止启动本机 Docker 或在本机执行容器构建/测试。以下为 CI 构建参数说明，不作为本机执行步骤：

```sh
docker build -f Dockerfile -t vf-comfyui-app:local .
docker build -f Dockerfile.worker --build-arg RUNTIME_REQUIREMENTS=requirements-runtime-cpu.lock --build-arg COMFYUI_DEVICE=cpu -t vf-comfyui-worker-cpu:local .
```

基础镜像固定为 Python 3.12.12 slim bookworm。`PYTHON_IMAGE` 只用于受控镜像源替换；换成不同基础环境后必须另行验证，不把该结果混同默认构建。配置、工作卷和令牌均不进入构建上下文。源码提取器可使用 `--archive` 校验离线原始 ZIP，目录须为空。

App 控制服务使用 `requirements-app.lock`；worker 的 CPU 验收配置使用 `requirements-runtime-cpu.in` 与同名 `.lock`，CUDA 后续配置使用 `requirements-runtime.in` 与同名 `.lock`。CPU/GPU 配置均固定 Python 3.12 Linux amd64 官方 wheel。解析依赖成功不等于镜像安装或运行已验证；依赖探测和运行验证在 5090 dev 执行。

本地研究宿主使用测试响应，不能作为 ComfyUI runtime、Studio 鉴权或生成验收证据。HTTP/WS 桥接只承载获准路由；生产接入还需要服务端逐主体、实例与项目鉴权。当前默认禁止生成、全局中断和在线依赖安装。`vf-embed.html` 应在实例目录的 `/` 路由返回，使上游资源和 API 基路径一致；不要把 HTML 文件名当作应用基路径。

桥接采用独立 MessagePort 与加载代次；页面切换或撤权时宿主必须调用 `dispose()`。适配器不是网络隔离的单独保证，部署时还须设置 iframe sandbox、CSP、静态资源 CORS 和服务端白名单，具体约束见设计仓库。

任务台账的状态推进方法只供内部执行器调用。内容完成仍须由后续可信 Artifact 适配器确认；本轮执行成功最多到 collecting。worker 代次变化会冻结派发，尚无自动解除排空或跨代次恢复接口；不确定任务不会自动重跑。输出描述不等于输出字节已保存。

## 3. 内部开发服务启动

基础实例目录只需要环境中的 `COMFYUI_APP_TOKEN`。配置 `project_origin` 后，还须提供 `COMFYUI_PROJECT_TOKEN`、`COMFYUI_AUTHORITY_TOKEN`；各凭据必须不同，每项至少 32 个 ASCII 字符、不含空白。不要在配置、命令行参数或 Git 中保存值。Project 地址必须是受控内部服务，不能使用外部用户 Bearer 替代内部凭据。未配置 Project 时目录可读，依赖 Project 的操作明确返回 `PROJECT_INTEGRATION_UNAVAILABLE`。

配置文件保存到忽略的 `data/config.json`，必填字段为 `database`、`alias`、`instance_id`、`organization_id`、`user_id`；可选 `project_origin`、`worker_origin`、`frontend_dir`、`listen` 和 `port`。主体及实例采用实际 UUIDv7；别名如 comfyuiA。默认不配置模型，能力查询会显示生成依赖未就绪。配置及实例主体是启动时绑定，修改归属须受控重启；项目成员权限在每次操作与派发前实时复验。

配置 `worker_origin` 后须提供独立的 `COMFYUI_WORKER_TOKEN`；目录经内部 `/vf/identity` 与 `/vf/status` 核对实例及 boot_id，失败时显示未知状态。Studio 通过已登记的 comfyui 内部服务地址及 `STUDIO_COMFYUI_SERVICE_TOKEN` 读取目录，该凭据对应本服务的 `COMFYUI_APP_TOKEN`。浏览器不接收这些凭据或 worker 地址，接口事实源见设计第 10.4 节。worker 身份与前端制品均就绪时目录开放编辑器；Studio 使用固定静态入口及受控 JSON/事件接口，不直接连 worker。

```sh
python -m app.server --config data/config.json
```

开发服务默认只监听本机回环地址；容器受控配置使用 `listen: "0.0.0.0"`，仍须由网络策略限制为 Studio 内部调用。不会启动 ComfyUI、下载模型或运行派发线程；入队不等于已开始生成。真实部署还须集成 worker 启动器、单进程约束、Studio 路由及网络隔离。不要直接对外暴露本服务或原生 8188。

编辑工具包含 session.open/renew/close 与 workflow.get/update；续租和草稿写入经过实时项目授权。租期 120 秒，更新需要 expected_version 和重试键。相同主体的另一窗口也需要独立会话，不能同时持有第二个编辑租约。本地草稿不会自动提交为 Project 修订。

机器定义更新先修改设计仓库，再运行 `scripts/sync_contract.py --source ...` 生成副本；`--check` 校验来源摘要及生成内容。测试中的 Project 与原生 ComfyUI 是本地 HTTP 后端，模型为无实际模型内容的测试字节；不作为真实数据库授权、模型或 GPU 验收。

## 4. 第一方 worker 启动器

在已准备好完整依赖的锁定 ComfyUI 源码环境中，使用 `python -m worker.launch --comfy-root /path/to/ComfyUI -- <上游参数>`。运行前由受控环境提供 `COMFYUI_INSTANCE_ID` 和独立的 `COMFYUI_WORKER_TOKEN`，不把值写到命令行或仓库。启动器保持上游 main 的初始化顺序，在 PromptServer 创建时安装门禁；缺少配置或安装失败即停止启动。

启动器强制关闭第三方 custom nodes 和外部 API 节点，拒绝启用节点白名单及在线 manager。第一方门禁通过启动器安装，不依赖 custom node 加载。原生路由仅开放执行器及基础编辑元数据/WS 所需的窄范围 API；编辑用途请求必须携带正确 boot_id 与用途头，不允许原生写入。上传与生成预览仍待 C6。

部署环境可通过 `COMFYUI_POD_UID`、`COMFYUI_POD_NAMESPACE`、`COMFYUI_POD_NAME`、`COMFYUI_CONTAINER_NAME` 注入当前 worker 容器绑定。该信息只在通过内部凭据与 boot_id 校验的状态接口返回；Studio 按绑定关联实例 CPU/内存采样，随后移除私有绑定。未配置不影响目录授权，资源保持未采集。

App 的 NativeClient 必须提供内部 worker 凭据。ExecutionAdapter 每次驱动先验证实例和进程 boot_id，再将 boot_id 绑定到所有原生读取与写入；启动标识变化使台账提升代次并冻结旧任务和会话。未知旧在途任务不自动接管，缺少原生任务记录不自动重提。此切片尚无跨代次解冻流程或持久接收协议。

历史本地验证包含实际 aiohttp 门禁、NativeClient HTTP 请求与启动器子进程，并曾运行官方 CPU runtime 联调基础编辑器。后续遵循工作区现行规范，在 5090 dev 验证。容器入口 `python -m worker.container` 固定工作卷 `/workspace`、上游源码 `/opt/comfyui` 和静态目录 `/opt/frontend`；CPU 镜像构建时设置 `COMFYUI_DEVICE=cpu`。容器由 UID/GID 10001 运行，挂载卷须可写，令牌从受控环境注入。C7 使用 CPU，GPU 留到 C6；没有 CI 发布或完整运行交付证据时，不宣称环境已就绪。

## 5. 文档依据

- [ComfyUI 设计与验收](https://github.com/verdantflarehub/verdantflare-design/blob/dev/docs/design/app/comfyui/README.md)。
- [ComfyUI 交付计划](https://github.com/verdantflarehub/verdantflare-design/blob/dev/plan/2026.10.comfyui-dev.plan.md)。
- [上游与分发说明](UPSTREAM.md)。

产品/API 和部署事实源由设计仓库维护。本项目仅维护源码、上游记录、构建与本地检查；后续分支仅使用 dev/release/main。
