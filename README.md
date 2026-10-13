# 栖网 LinkNest

## 简介

LinkNest 是单容器网络服务控制台，提供反向代理、TCP / UDP 端口转发、阿里云动态域名与证书申请、轻面板、网络唤醒、访问过滤和 SSH Web 终端。

当前版本 **1.0.0**，发布镜像支持 **Linux ARM64**，适用于 ARM64 NAS / 路由器；其他架构可自行构建。前端为内嵌 HTML / CSS / JavaScript，无需 Node 构建。第三方资源与许可见 [THIRD_PARTY.md](THIRD_PARTY.md)。

本项目尚未经独立安全审计，管理入口建议仅在受信局域网或 SSH 隧道中访问。自动封禁与名单订阅默认关闭，详见 [访问过滤](docs/access-filter.md)。

## 如何构建、导入与使用

### 获取镜像

从 Docker Hub 拉取（Linux ARM64）：

```sh
docker pull jacoyyyy/linknest:1.0.0
```

在源码目录构建，默认构建宿主机架构，期间执行 Go 测试：

```sh
docker build -t jacoyyyy/linknest:1.0.0 .
```

依赖下载困难时可追加 `--build-arg GOPROXY=https://goproxy.cn,direct`。源码测试方法见 [测试说明](docs/testing.md)。

离线导出、导入镜像：

```sh
# 在已有镜像的设备上导出
docker save jacoyyyy/linknest:1.0.0 | gzip > linknest-1.0.0-linux-arm64.tar.gz
# 复制到另一台 ARM64 设备后导入
gzip -dc linknest-1.0.0-linux-arm64.tar.gz | docker load
```

### 本机试用

```sh
docker run -d --name linknest \
  --restart unless-stopped \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:size=8m \
  --memory 192m --pids-limit 128 --stop-timeout 40 \
  --log-opt max-size=5m --log-opt max-file=2 \
  -p 127.0.0.1:17880:17880 \
  -e LINKNEST_ADMIN_ADDR=0.0.0.0:17880 \
  -e LINKNEST_FIREWALL=disabled \
  -v linknest-data:/data \
  jacoyyyy/linknest:1.0.0
```

访问 `http://127.0.0.1:17880`。远程设备可建立隧道：`ssh -N -L 17880:127.0.0.1:17880 -p <SSH端口> root@<设备IP>`。

也可执行 `docker compose up -d --build`，附带配置同样只开放本机管理端口。Compose 数据卷名称带项目名前缀，用 `docker inspect linknest` 查看实际挂载。试用模式只映射管理端口，业务入口需额外映射对应端口，或使用 host 网络。

### 路由器 / NAS 部署

以下适用于 Linux host 网络与 legacy iptables。将 `192.168.1.1` 替换成真实 LAN IP。无需自动防火墙时，删除两个 `--cap-add`、锁挂载，并将 `LINKNEST_FIREWALL` 改为 `disabled`。

```sh
touch /run/xtables.lock
docker run -d --name linknest \
  --network host --restart unless-stopped \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:size=8m \
  --memory 192m --pids-limit 128 --stop-timeout 40 \
  --log-opt max-size=5m --log-opt max-file=2 \
  -e LINKNEST_ADMIN_ADDR=192.168.1.1:17880 \
  -e LINKNEST_FIREWALL=enabled \
  --mount type=bind,source=/run/xtables.lock,target=/run/xtables.lock \
  -v linknest-data:/data \
  jacoyyyy/linknest:1.0.0
```

自动放行与内核转发需要较高网络权限，仅管理 LinkNest 自有规则，不清空宿主防火墙；不需要独立权限助手。不要使用 `--privileged` 或挂载 Docker Socket。WOL 广播建议使用 host 网络；公网可达仍取决于上级路由、运营商和防火墙。

首次初始化读取一次性口令：

```sh
docker exec linknest cat /data/bootstrap.token
```

在页面输入口令，创建管理员用户名与 12—72 字节密码；没有默认账号密码，初始化后口令文件删除。随后配置业务规则、DNS 凭据和证书。管理 HTTPS 需在设置中选择有效证书并开启，不会在申请成功后自动开启。

升级前备份，拉取新镜像后用原参数重建容器，保留原数据卷。同名容器需先停止并移除；**不要删除数据卷**。

## 项目结构

```text
cmd/linknest/       程序入口
internal/app/       配置、代理、DNS、证书、面板、WOL、终端与回归测试
internal/access/    访问过滤、封禁、订阅与单元测试
web/                页面、样式、脚本、图标和第三方终端资源
scripts/            构建、界面回归与隔离容器验证
docs/               功能和测试说明
Dockerfile          源码构建镜像
Dockerfile.runtime  预编译程序与许可文件构建镜像
compose.yaml        仅开放本机的试用部署
go.mod / go.sum     Go 依赖
THIRD_PARTY.md      第三方资源与许可说明
```

`bin/`、`dist/` 为本地构建 / 交付目录，不进入 Git 或 Docker 构建上下文。有效测试保留在源码中，不进入运行镜像。

## 数据位置与备份

持久数据位于容器 `/data`，上述 `docker run` 使用命名卷 `linknest-data`。用 `docker volume inspect linknest-data` 查看实际位置，不要直接修改 Docker 内部目录。

```text
/data/
  config.json           规则与加密凭据
  master.key            解密密钥，必须随配置备份
  auth.json             管理账号与密码哈希
  bootstrap.token       仅初始化前存在
  access/               封禁状态、名单缓存与更新状态
  icons/                已选择的本地图标缓存
  certificate-jobs.json 证书任务过程
  certificates/         证书、私钥、续期参数与 ACME 密钥
```

**配置导出不是完整备份**，不包含全部凭据、账号和证书。迁移需备份整个数据卷；丢失 `master.key` 后无法解密原凭据。备份含敏感信息，不要上传仓库或镜像。

在已有镜像的设备上停止容器后备份：

```sh
mkdir -p linknest-backups
docker stop linknest
docker run --rm --network none --entrypoint tar \
  -v linknest-data:/data:ro \
  --mount "type=bind,source=$(pwd)/linknest-backups,target=/backup" \
  jacoyyyy/linknest:1.0.0 -czf /backup/linknest-data.tar.gz -C /data .
docker start linknest
```

确认备份成功后再升级。恢复时先停止 LinkNest，将备份解压到**新的空数据卷**，再用该卷启动；不要与已有数据混合。日志用 `docker logs linknest` 查看，示例已配置轮转。
