# 反向代理与 WebSocket

## 自动请求头

LinkNest 在转发前移除客户端传入的 `Forwarded` 和 `X-Forwarded-*` 标准来源头，按实际连接重建：

| 请求头 | 行为 |
| --- | --- |
| `X-Forwarded-For` | 连接到 LinkNest 的客户端 IP，不信任客户端自报的地址链 |
| `X-Forwarded-Host` | 原始访问域名和端口，例如 `motrix.example.com:8888` |
| `X-Forwarded-Proto` | HTTPS 由 LinkNest 终止时为 `https`，明文入口为 `http`；不取决于后端协议 |
| `Host` | 默认使用后端地址；开启子规则「保留访问域名（Host）」后使用原始访问域名和端口 |

这些行为对普通 HTTP 和 WebSocket 握手一致，不需要手工添加请求头。若 LinkNest 前还有一层 TLS 终止代理，不能仅靠客户端传入的 `X-Forwarded-Proto` 声称 HTTPS；目前不提供可信前置代理配置。

## WebSocket 自动转发

普通 HTTP/HTTPS 后端地址已经自动支持 HTTP/1.1 WebSocket Upgrade，无须单独开关；保留子协议、路径、查询参数和鉴权头，握手成功后双向转发。支持文本、二进制和 Ping/Pong；停用整个监听入口时关闭已升级连接。

新增显式 `ws://`、`wss://` 后端地址支持：内部按 `http://`、`https://` 完成握手和转发，不改变已有 HTTP/HTTPS 配置。后端基础地址不能包含用户名、密码、查询参数或片段；请求自身的查询参数会正常转发。

`wss://` 和 `https://` 后端默认校验证书。只有可信的自签名后端才考虑开启「跳过后端 TLS 证书验证」；普通 HTTP 后端不需要该选项。

## Motrix 示例

- 主规则：HTTPS 监听 `8888`，选择覆盖 `motrix.example.com` 的有效证书。
- 子规则：域名 `motrix.example.com`，后端 `http://192.168.1.100:8088`，替换为实际 NAS 地址。
- 开启「保留访问域名（Host）」；通常不要开启「同源请求来源适配」，它不是 WebSocket 开关。
- Motrix 设置 `MOTRIX_PUBLIC_URL=https://motrix.example.com:8888`。

浏览器访问 HTTPS 面板，实时事件通过相同入口的 WSS 转发，无需额外开放 MDXP 或 aria2 RPC。完整面板的后端仍填写 HTTP 根地址，不要改成仅含事件路径的 WS 地址。

## 1.2.0 路径分流

每条外部后端子规则可填写 `pathPrefix`。旧配置迁移为 `/`。同一主规则可以使用相同域名、不同路径；跨主规则的域名归属仍唯一。

| 域名 | 路径前缀 | 后端 |
| --- | --- | --- |
| app.example.com | /bridge/ | http://192.0.2.10:16801 |
| app.example.com | / | http://192.0.2.10:8088 |

先选最具体的域名，再选最长路径段前缀。`/bridge/` 匹配 `/bridge` 与 `/bridge/x`，不匹配 `/bridge-other/`。精确域名下没有符合的路径时返回 404，不落入其他域名的默认后端。前缀不能包含 `.`、`..` 路径段、重复斜杠、查询串或百分号编码。

转发保留原路径、查询参数和编码；若后端 URL 自带基础路径，则按已有反代语义拼接。HTTP、WS/WSS 使用同一套路由，TLS/SNI 证书选择仅取决于域名。Host、Origin 适配及 Upgrade 行为保持原设置。内置轻面板和 WOL 当前仅允许 `/`，避免其绝对资源路径失效。
