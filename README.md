# Visual Window App：C 窗口工程资源包管理

本项目为 SDL2 C 窗口程序增加了一套可离线运行的资源包管理系统：

- 终端（C11）负责路径解析、SHA256 校验、不可变包安装、原子切换、回退和本地垃圾回收。
- 服务端（Python 标准库）生成不可变包，维护 SQLite 关系库，并按设备分组发布。
- Web 控制台展示包、分组发布记录、媒体元数据、布局依赖和缺文件原因。
- GUI 在背景、字体或图标缺失时仍绘制内置基本操作界面，不把“无图”变成致命错误。

## 目录

```text
src/
  main.c                 SDL 窗口入口
  renderer.c/h           背景渲染 + 无资源内置界面
  window.c/h             SDL 窗口
  resource_tool.c        终端 CLI
  resource_paths.c/h     根目录优先级、安全相对路径、原子文件操作
  resource_pkg.c/h       RESOURCEPKG/1 包格式、安装、切换、回退
  resource_client.c/h    分组更新、设备身份、状态、本地 GC
  http_client.c/h        小型 HTTP/1.x 客户端
  sha256.c/h             无外部依赖 SHA256
server/
  resource_server.py     打包/发布/回退/GC/HTTP API/CLI
  web/                   管理页面（无第三方 CDN）
test/integration_test.sh 端到端验证
```

## 快速构建与验证

无 GUI 依赖的环境默认构建可移植资源工具：

```bash
make tool
make test
```

安装 SDL2 开发库后可构建窗口程序；容器中：

```bash
make tool
make app
```

启动演示服务：

```bash
python3 server/resource_server.py --state state init-demo
python3 server/resource_server.py --state state serve --host 127.0.0.1 --port 8088
```

打开：

```text
http://127.0.0.1:8088/
```

终端命令：

```bash
# 初始化可写资源根
./resource-tool init --root /path/to/资源根

# 离线安装；包可通过 U 盘、局域网共享或预烧录方式携带
./resource-tool install package.rrpkg --root /path/to/资源根

# 加入设备分组并更新
./resource-tool update --server http://127.0.0.1:8088 --group factory --root /path/to/资源根

# 解析当前激活版本中的逻辑路径
./resource-tool resolve backgrounds/background.png --root /path/to/资源根

# 查看 current/previous 完整性
./resource-tool status --root /path/to/资源根

# 回退到上一完整版本
./resource-tool rollback --root /path/to/资源根

# 垃圾回收
./resource-tool gc --root /path/to/资源根
```

## 路径优先级与安全边界

解析“写入/状态根”的优先级是：

1. CLI 参数：`--root DIR`
2. 环境变量：`VISUAL_RESOURCE_ROOT`
3. 可执行文件旁边的安装目录：`<exe目录>/resources`
4. 可执行文件相邻的便携目录：`<exe目录>/../resources`
5. 用户缓存：`$XDG_CACHE_HOME/visual-window-app/resources`
6. 用户默认缓存：`$HOME/.cache/visual-window-app/resources`
7. 当前工作目录：`.visual-resources`

关键约束：

- 程序不依赖构建机源码路径，也不要求在 `/workspace`、开发用户目录下运行。
- 包内只允许普通 UTF-8 相对路径；拒绝绝对路径、盘符、反斜杠、`..`、`.`、符号链接逃逸和 URL。
- blob 使用内容指纹 `blobs/<sha256前2位>/<sha256>`，逻辑路径不能逃出资源根。
- `resolve` 只从 `current.state` 指向的完整版本解析，不扫描来路不明的文件。

资源根布局：

```text
root/
  current.state          当前显示指针
  previous.state         回退保留指针
  device.state           本机随机设备身份
  blobs/xx/<sha256>      内容寻址文件，可跨包去重复用
  meta/releases/<id>.idx 不可变包索引
  tmp/                   下载/解包临时区
  packages/              可保留的离线包
```

## 不可变包格式

`RESOURCEPKG/1` 由索引头和顺序 blob 数据组成：

```text
RESOURCEPKG/1
package-id: <索引内容身份>
version: 1.0.0
release-id: rel-1-0-0
created-at: ...
manifest-sha256: ...
index-sha256: ...
package-size: 00000000000001727744
entry-count: 4
<sha256> <size> <media-type> <logical-path>
...
BLOBS
<binary blob 1><binary blob 2>...
```

`manifest.json` 本身也是一个 blob，描述：

- 内容指纹 `sha256`
- 媒体类型
- 文件大小
- 图片宽高
- 布局依赖，如 `window:1280x720`、`ui:status-panel`
- 是否必需

安装时逐 blob 写入临时文件并校验 SHA256；全部 blob 到位后才写入 `meta/releases/<id>.idx` 并替换状态指针。包只下载一半、磁盘不足、校验失败或索引被篡改时，不修改 `current.state`，旧版本继续可用。

## 整体包切换与按文件复用的比较

| 方案 | 原子性 | 离线安装 | 空间占用 | 回退代价 | 适合场景 |
|---|---|---|---|---|---|
| 每版整包目录，整体切换 | 指针/目录切换简单 | 很简单 | 相同背景、字体、图标重复存放，浪费明显 | 很低，切目录即可 | 包很小、介质充足 |
| 只做逐文件差分，逐个覆盖 | 差分包小 | 需要补依赖链，易出现半新半旧 | 最低 | 可能要重新下载旧文件，校验复杂 | 常在线、带宽紧张 |
| **整体包校验 + 内容寻址 blob 去重（本实现）** | 以包为单位验证，状态指针原子切换 | 一个 `.rrpkg` 即可离线安装 | 相同文件只占一份 | 只保留两个小 state 指针和所需 blob，无需重下 | GUI 资源、字体图标复用、便携/弱网设备 |

本实现选择第三种：**下载和信任边界是完整不可变包，存储层按 SHA256 去重复用**。这保留了整体切换的原子性和回退确定性，又避免整包目录重复占空间。

## 原子更新与回退

- 新版本先进入 `tmp/`，逐 blob 验证后并入内容寻址存储。
- 只有所有引用 blob 完整，才创建新 release index。
- 激活时保存旧指针，替换 `current.state`，同时写入 `previous.state`。
- 回退先验证 previous 引用的每个 blob；完整才交换，不完整则拒绝。
- 当前显示版本和回退版本的状态文件分离，避免“半新半旧”。

## 服务端关系库

SQLite 中的核心表：

- `files`：文件身份、媒体类型、尺寸、宽高、创建时间、`ref_count`
- `packages`：不可变包 ID、版本、包大小、manifest 指纹
- `package_files`：包与文件多对多关系、逻辑路径、布局依赖、必需性
- `device_groups`：设备分组
- `devices`：设备身份与所属分组
- `group_releases`：每个分组的 `pending/current/rollback` 发布记录
- `device_events`：设备安装/激活事件
- `missing_reports`：终端上报的缺文件原因

`files.ref_count` 由 `package_files` 触发器维护，回答“这个 blob 被多少包成员引用”；真正删除还要同时满足发布引用不可达。

## 三类 GC 引用

本地和服务端都不能按“最近没下载/最近没访问”删除文件。GC 根只有：

1. **当前显示**：分组或终端的 `current`。
2. **待发布**：分组的 `pending`。
3. **回退保留**：分组或终端的 `rollback` / `previous`。

终端 GC 仅遍历 `current.state` 与 `previous.state` 中的包成员；损坏临时文件可清理，但完整且被引用的 blob 即使很久未下载也不会删除。回退保留可由服务端策略过期；过期依据是发布状态和保留期限，不是下载时间。

## 设备分组认领

- 设备首次运行生成本机随机 64 位十六进制 ID。
- enroll 时绑定分组；同组已有其他设备时返回 `409`，后续资源请求返回 `403`。
- 分配接口只返回该设备所属分组的 release。
- index/package 下载都要求 `X-Device-ID` 与发布分组一致，防止两台设备错领资源。

## Web 缺文件诊断

Web 页面调用 `/api/diagnostics`，准确列出：

- 服务端 blob 不存在
- 大小与清单不一致
- SHA256 内容指纹不匹配
- 媒体类型缺失
- 终端通过 `/api/missing` 上报的逻辑路径、期望指纹和原因

它用于解释“为什么这个背景、字体或图标没有出现”，而不是只显示一个碎图。

## 已覆盖的验证

`test/integration_test.sh` 覆盖：

1. 便携离线安装
2. 安装目录包含中文
3. 包截断时旧版本继续可用
4. `../` 相对路径逃逸拒绝
5. 在线 v1 → v2 原子切换
6. 本机回滚
7. 两台设备不能认领同一分组资源
8. 模拟缓存空间不足，当前版本不被破坏
9. GC 保留 current/previous 两类本地引用
10. 服务端删除 blob 后，Web API 列出准确原因
11. 字体/图标缺失时终端给出明确 missing 原因，GUI 内置基本操作界面仍可绘制

## Docker / noVNC

```bash
docker compose up --build
```

浏览器访问：

```text
http://localhost:6080
```

noVNC 只承载远程显示；资源管理逻辑运行在容器内的 C 程序和 HTTP 服务中。
