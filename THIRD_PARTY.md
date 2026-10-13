# 第三方组件

访问过滤可选订阅 [Spamhaus Project DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)，免费使用须署名并保留原文日期及版权；不得每小时多于一次抓取。未启用时不请求，名单不打包进镜像。其他订阅按各自许可执行。

轻面板视觉布局参考用户提供的 Lucky 截图；前端独立实现，未复制 Lucky 源码或内置素材。

- Go 标准库：BSD-3-Clause，构建工具链 Go 1.26.9。
- golang.org/x/crypto v0.48.0（ACME、SSH、bcrypt）：BSD-3-Clause。
- golang.org/x/sys v0.41.0（间接依赖）：BSD-3-Clause。
- github.com/gorilla/websocket v1.5.3：BSD-2-Clause。
- github.com/skip2/go-qrcode：MIT；本地生成两步验证二维码，不调用外部二维码服务。版本锁定在 go.mod / go.sum。
- @xterm/xterm 5.5.0：MIT；静态资源来自 npm 官方发布包，许可证见 `web/vendor/LICENSE`。
- Debian bookworm、iptables、ca-certificates、tzdata：随镜像发行的许可证位于 `/usr/share/doc/*/copyright`。

Go 模块版本及校验值锁定在 go.mod / go.sum。xterm.js 离线内置，不加载外部 CDN。
镜像编译会将 Go 依赖许可证复制到 `/usr/share/doc/linknest`。

默认图标源为 [Iconify API](https://iconify.design/docs/api/)。镜像不打包第三方图标全集，用户查询并选用图标时访问对应 API。各图标集许可证不同，品牌图标还可能涉及商标；使用或再分发前请核对 [Iconify 图标集许可](https://iconify.design/docs/icons/icon-basics.html)。缓存图标不改变原许可，数据卷中的用户选图不包含在源码发布包中。

另提供 [selfh.st/icons](https://github.com/selfhst/icons) 官方目录，通过 jsDelivr 获取目录和用户所选图标。目录在浏览器本地搜索，不上传搜索词；请求仍会向 CDN 暴露网络地址。图标所属品牌及相关许可按上游说明执行，缓存不改变其权利归属；镜像不内置该图标全集。
