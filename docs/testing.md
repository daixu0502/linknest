# LinkNest 1.0.0 测试

## 运行

```sh
go test ./...
go vet ./...
node scripts/test-ui.mjs
node scripts/test-workflows.mjs
node scripts/test-panel.mjs
node scripts/test-security.mjs
go build -trimpath -o bin/linknest ./cmd/linknest
```

可选 `go test -race ./...` 需支持的 CGO 工具链。ARM64 交叉编译使用 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`；编译成功不等于在设备运行成功。

## 自动回归范围

- 旧配置迁移、加密密钥、账户、HTTPS 会话与 CSRF。
- 共享端口域名路由、TLS、HTTP 跳转、来源适配、TCP/UDP、内核 NAT 自有链边界。
- DDNS 类型、删除远端确认、更新与凭据；证书长期任务及保护。
- 轻面板、图标缓存、WOL、SSH 指纹确认、终端；前端布局 / 滚动 / 登录语义。
- 异常响应时间窗、阈值、白名单、内网豁免、IPv6、到期解封、单独解封 / 清空自动记录、保存及重启恢复。
- 不信任 X-Forwarded-For；代理 404 达阈值后的拒绝，WebSocket / 流式响应保留。
- 纯文本 / Spamhaus JSON、去重、非法 / 空内容、HTTPS / DNS / 保留地址防护、更新冷却及重启、各源独立更新、失败保留旧缓存、改 URL 不复用旧列表、停用 / 删除退出过滤。
- 访问过滤 API 登录与 CSRF；前端 IPv6 解封、输入转义、预设与策略表单。

## 设备隔离验证

`scripts/smoke-container.py <容器名>` 只操作具有 `linknest.test=true` 标签、无附加权限、仅绑定本机的临时容器和新数据卷。检查初始化、鉴权、版本、schema、代理、TCP、前端资源及停用 / 退出。

## 限制

未代替第三方安全审计、DDoS 压测、真实 iOS / Android WebView 验证。自动封禁 / 订阅不用于内核 NAT；大名单不展开成数万条宿主 iptables 规则。不在生产制造异常请求、启用名单或删除真实 DNS 来测试。
