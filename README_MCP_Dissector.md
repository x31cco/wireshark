# Wireshark MCP Dissector

一个用于解析 Model Context Protocol (MCP) 的 Wireshark 插件。

## 功能

- ✅ 解析 MCP 的 JSON-RPC 2.0 消息
- ✅ 识别 MCP 方法调用 (tools/list, tools/call, resources/read 等)
- ✅ 支持 SSE (Server-Sent Events) 流式响应
- ✅ 显示错误信息 (包含错误码和错误消息)
- ✅ 启发式检测 - 自动识别 HTTP 中的 MCP 流量
- ✅ 支持工具名称、资源URI、提示名称等字段解析

## 支持的 MCP 方法

### 客户端 → 服务器
- `initialize` - 初始化 MCP 连接
- `tools/list` - 列出可用工具
- `tools/call` - 调用工具
- `resources/list` - 列出资源
- `resources/read` - 读取资源
- `resources/subscribe` - 订阅资源更新
- `resources/unsubscribe` - 取消订阅
- `prompt/list` - 列出提示
- `prompt/get` - 获取提示
- `roots/list` - 列出根目录
- `sampling/createMessage` - 请求 LLM 采样

### 服务器 → 客户端
- `initialized` - 确认初始化
- 上述方法的响应

### SSE 事件类型
- `tools/list` - 工具列表更新
- `resources/list` - 资源列表更新
- `resources/update` - 资源内容更新
- `message` - 采样消息结果

## JSON-RPC 错误码

| 错误码 | 含义 |
|--------|------|
| -32700 | 解析错误 |
| -32600 | 无效请求 |
| -32601 | 方法未找到 |
| -32602 | 无效参数 |
| -32603 | 内部错误 |
| -32000 | 服务器错误 |

## 编译

### 方法 1: 手动编译 (Linux/macOS)

```bash
# 进入 Wireshark 源码目录
cd wireshark

# 创建构建目录
mkdir build && cd build
cmake ..

# 复制源文件到插件目录
cp /path/to/packet-mcp.c plugins/epan/dissectors/

# 编译插件
make packet-mcp.so
```

### 方法 2: 使用 CMake

将 `packet-mcp.c` 和 `CMakeLists.txt` 放到 `wireshark/plugins/epan/dissectors/` 然后重新编译。

### Windows

需要安装 Visual Studio 和 Wireshark 开发环境，然后使用 CMake 或 nmake 编译。

## 安装

### Linux/macOS
```bash
cp packet-mcp.so ~/.local/lib/wireshark/plugins/
# 或
cp packet-mcp.so /usr/lib/wireshark/plugins/
```

### Windows
```bash
copy packet-mcp.dll %APPDATA%\Wireshark\plugins\
```

## 使用

1. 启动 Wireshark
2. 捕获 HTTP 流量 (默认端口 3000 或其他 MCP 端口)
3. MCP 流量会被自动识别并解析
4. 在过滤器中输入 `mcp` 查看 MCP 流量

### 过滤器示例

```bash
mcp.method == "tools/list"       # 查看工具列表请求
mcp.method == "tools/call"       # 查看工具调用
mcp.result                       # 查看结果
mcp.error                       # 查看错误
mcp.error.code == -32601        # 查看"方法未找到"错误
mcp.sse.event                   # 查看 SSE 事件
mcp.tool.name == "my_tool"      # 查看特定工具
mcp.resource.uri == "file://..." # 查看特定资源
```

### 过滤器字段

| 字段 | 说明 |
|------|------|
| `mcp.method` | MCP 方法名 |
| `mcp.jsonrpc` | JSON-RPC 版本 |
| `mcp.id.num` | 消息 ID (数字) |
| `mcp.params` | 方法参数 |
| `mcp.result` | 方法结果 |
| `mcp.error` | 错误信息 |
| `mcp.error.code` | 错误码 |
| `mcp.error.message` | 错误消息 |
| `mcp.sse.event` | SSE 事件类型 |
| `mcp.sse.data` | SSE 数据 |
| `mcp.tool.name` | 工具名称 |
| `mcp.tool.input` | 工具输入参数 |
| `mcp.resource.uri` | 资源 URI |

## 注意事项

- 需要 Wireshark 3.x 或 4.x
- MCP 流量通常通过 HTTP 传输
- 某些 MCP 实现使用 stdio (本地进程)，这种无法通过网络抓包捕获

## 扩展

可以进一步扩展的功能：
- 更完整的 JSON 解析
- 特定方法的格式化输出
- 统计和图表
- 专家信息 (Expert Info)

## 版本历史

### v1.1 (当前版本)
- 添加了 SSE 解析支持
- 添加了启发式 HTTP 检测
- 添加了更多字段 (工具、资源、提示)
- 添加了 JSON-RPC 错误码解析

### v1.0
- 初始版本
- 基本 JSON-RPC 解析

---

Made with ❤️ by 小乐宝
