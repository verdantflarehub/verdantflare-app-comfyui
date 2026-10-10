# ComfyUI 上游记录

## 1. 来源与边界

固定源码及前端版本由 `upstream.lock.json` 管理。本体和官方前端分别核对；Linux Python 3.12/CUDA 13.0 依赖另由 `requirements-runtime.lock` 锁定，App 使用 `requirements-app.lock`。哈希锁解析成功不表示安装或 GPU 镜像已构建；基础包没有模型依赖。

C7 按用户决定先用 CPU；CPU 配置的输入与锁分别为 `requirements-runtime-cpu.in`、`requirements-runtime-cpu.lock`。官方 torch/torchvision/torchaudio CPU wheel 使用独立 URL 和 SHA-256，避免仅改变启动参数却携带 CUDA 依赖。镜像由 CI 构建，运行验证在 5090 dev 完成。

官方前端包来自 PyPI，下载字节必须同时满足锁定大小和 SHA-256。构建工具提取静态文件并生成独立 VF 嵌入入口；VF 兼容适配在入口中先于官方模块执行。原始 wheel 的哈希保持独立记录。

基础编辑器联调定位到上游 appModeStore 在 graph 初始化前读取 rootGraph，导致启动错误日志。当前制品包含 `app-mode-graph-ready-1` 一处补丁：先检查上游已有的 isGraphReady，再绑定 configured 事件。对应源码差异在 `frontend/app-mode-startup.patch`，固定上游源码、目标 bundle 原始 SHA-256 和单一替换片段在 `upstream.lock.json`；输入/输出摘要或匹配数量不符时拒绝构建，不对新版本盲目替换。其余官方 bundle 保持原字节，输出补丁摘要写入 `build/frontend/vf-build.json`。

## 2. 许可与分发

官方前端为 GPL-3.0-only；ComfyUI 本体的固定源码保留其 LICENSE；源码校验提取器强制要求该文件存在。`prepare_frontend.py` 保留 wheel 内许可证及元数据，分发前须同时提供匹配源码、依赖许可、VF 修改和可重建说明。当前仅本地研究和开发，未发布镜像或前端包。

浏览器 Storage 兼容值只在实例加载期存在，不保存身份；基础编辑器的设置、JSON 工作流文件和当前实例草稿经授权 App 后端持久化，不代表 Project 保存。

## 3. 当前依据

- [ComfyUI 固定源码](https://github.com/Comfy-Org/ComfyUI/tree/c2bcbecd82ec5ae66594340b395c24ef0217b238)。
- [官方前端固定源码](https://github.com/Comfy-Org/ComfyUI_frontend/tree/6d6af63c00f132cd25dc29307fc56bd2c094fa22)。
- [官方前端 PyPI 1.48.7](https://pypi.org/project/comfyui-frontend-package/1.48.7/)。
