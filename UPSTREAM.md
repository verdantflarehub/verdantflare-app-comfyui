# ComfyUI 上游记录

## 1. 来源与边界

固定源码及前端版本由 `upstream.lock.json` 管理。本体和官方前端分别核对；锁文件不表示 Python/CUDA/模型依赖已经全部锁定，也不表示 GPU 镜像已构建。

官方前端包来自 PyPI，下载字节必须同时满足锁定大小和 SHA-256。构建工具提取静态文件并生成独立 VF 嵌入入口，不修改官方 JavaScript 构建产物。VF 兼容适配在入口中先于官方模块执行。

## 2. 许可与分发

官方前端为 GPL-3.0-only；ComfyUI 本体许可按固定源码核对。`prepare_frontend.py` 保留 wheel 内许可证及元数据，分发前须同时提供匹配源码、依赖许可、VF 修改和可重建说明。当前仅本地研究和开发，未发布镜像或前端包。

浏览器临时偏好使用实例加载期的内存 Storage 兼容层，不代表工作流、项目或身份持久化。后续正式用户资料必须经授权后端保存。

## 3. 当前依据

- [ComfyUI 固定源码](https://github.com/Comfy-Org/ComfyUI/tree/c2bcbecd82ec5ae66594340b395c24ef0217b238)。
- [官方前端固定源码](https://github.com/Comfy-Org/ComfyUI_frontend/tree/6d6af63c00f132cd25dc29307fc56bd2c094fa22)。
- [官方前端 PyPI 1.48.7](https://pypi.org/project/comfyui-frontend-package/1.48.7/)。
