# LinkNest 1.1.1 测试

## 运行

```sh
go test ./...
go vet ./...
node scripts/test-ui.mjs
node scripts/test-workflows.mjs
node scripts/test-panel.mjs
node scripts/test-security.mjs
node scripts/test-twofactor.mjs
node scripts/test-notices.mjs
node scripts/test-interaction.mjs
node scripts/test-upnp.mjs
go build -trimpath -o bin/linknest ./cmd/linknest
```

可选 `go test -race ./...` 需支持的 CGO 工具链。ARM64 交叉编译使用 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`；编译成功不等于在设备运行成功。

## 自动回归范围

- UPnP 服务发现、同地址控制 URL、无代理/跳转、SOAP 错误、映射增删改与竞争保护、失败恢复；与 LinkNest 规则冲突、登录/CSRF、并发拒绝和独立数据保存。
- UPnP 刷新保留旧内容、后台状态轮询不重建页面、相同内容保留 DOM 与焦点；慢请求合并、失败保留上次结果、会话失效清空缓存及丢弃过期响应；桌面与手机验证卡片高度稳定。
- UPnP 原厂黑名单仅操作自有 UCI / INPUT 规则；模拟预检查失败、应用失败、并发写与回滚。跨设备管理开关模拟开启、关闭、取消及 EOF 回滚；SSH 指纹校验与两阶段确认、现有映射保留检查。原厂模式切换不在生产自动触发。
- 原厂 UPnP 启动、停止及回滚路径显式关闭子进程锁描述符；模拟服务拒绝继承事务锁，避免守护进程持续占锁导致后续黑名单应用失败。

- 旧配置迁移、加密密钥、账户、HTTPS 会话与 CSRF。
- 两步验证：RFC 6238 向量、本地二维码、密码单独不能登录、时钟偏差与防重放、一次性恢复码及并发消费、绑定有效期 / 会话限制、限流、重启与账号变更保留、恢复码轮换与关闭、密钥缺失拒绝启动、分步弹窗切换。
- 共享端口域名路由、TLS、HTTP 跳转、来源适配、TCP/UDP、内核 NAT 自有链边界。
- 反代 HTTP/HTTPS 自动来源头及伪造头清除；WS/WSS 与 HTTP/HTTPS 后端、证书校验、子协议、服务端推送、文本/二进制大帧、Ping/Pong、路径查询、来源保护及停用入口断开升级连接。
- DDNS 类型、删除远端确认、更新与凭据；证书长期任务及保护。
- 路由器公网 IPv4 / IPv6 非阻塞读取、单次共享刷新、冷却、独立失败与旧值标记；服务状态文案统一。
- 说明提示会话隐藏、持久不提示、恢复仅清理自身设置、存储不可用降级；故障警告不可隐藏。
- 操作确认使用独立、不可隐藏的说明，即使同文帮助已被隐藏仍显示；桌面和手机反代条件区域不占隐藏空间、不横向溢出，末尾开关保持紧凑间距。可选 `node scripts/test-dialog-layout.cjs` 使用 Playwright（可用 `EDGE_PATH` 指定浏览器）。
- 端口转发核对本机监听及路由器可达的 NAT / UPnP / PCP 映射，按 IPv4/IPv6、协议、地址与端口范围区分；排除自有链、未挂接链与 OUTPUT 映射；读取失败不误报正常。冲突出现时撤下兼容监听，移除外部冲突后自动重试；不改外部映射。
- 总览统计卡片直达、布局与快捷操作移除；下拉菜单独立浮层、上下展开与边界限制、不撑大弹窗或挤动字段，关闭后恢复归属；圆形刷新及错误恢复、页面切换动画与减少动态效果支持。
- 单箭头刷新图标；后台与公共轻面板 / WOL 共用按钮反馈，悬停、键盘焦点、触屏按下、禁用状态与危险操作辨识，边框不改变尺寸。
- 轻面板、图标缓存、WOL、SSH 指纹确认、终端；前端布局 / 滚动 / 登录语义。
- 异常响应时间窗、阈值、白名单、内网豁免、IPv6、到期解封、单独解封 / 清空自动记录、保存及重启恢复。
- 不信任 X-Forwarded-For；代理 404 达阈值后的拒绝，WebSocket / 流式响应保留。
- 纯文本 / Spamhaus JSON、去重、非法 / 空内容、HTTPS / DNS / 保留地址防护、更新冷却及重启、各源独立更新、失败保留旧缓存、改 URL 不复用旧列表、停用 / 删除退出过滤。
- 访问过滤 API 登录与 CSRF；前端 IPv6 解封、输入转义、预设与策略表单。

## 设备隔离验证

`scripts/smoke-container.py <容器名>` 只操作具有 `linknest.test=true` 标签、无附加权限、仅绑定本机的临时容器和新数据卷。检查初始化、鉴权、版本、schema、代理、TCP、前端资源及停用 / 退出。

## 限制

未代替第三方安全审计、DDoS 压测、真实 iOS / Android WebView 验证。自动封禁 / 订阅不用于内核 NAT；大名单不展开成数万条宿主 iptables 规则。不在生产制造异常请求、启用名单或删除真实 DNS 来测试。
