# 镜像构建与发布

发布镜像分为独立的运行环境和当前程序。禁止使用 `jacoyyyy/linknest:<旧版本>` 或 `latest` 作为后续发布的基础镜像，也不通过追加程序层更新旧应用镜像。

## 常规源码构建

仓库根目录的 `Dockerfile` 使用 Go 构建阶段及全新的 Debian 运行阶段：

```sh
docker build --platform linux/arm64 -t jacoyyyy/linknest:1.1.5 .
```

## 离线交叉编译发布

运行环境只包含 Debian、CA 证书、iptables 和时区数据，不包含 LinkNest 程序、许可目录或配置。先独立构建并保存，更新系统依赖时再重建：

```sh
mkdir -p .tools/runtime-base
docker build --platform linux/arm64 -f Dockerfile.runtime-base -t linknest-runtime:bookworm-arm64 .
docker image save -o .tools/runtime-base/bookworm-arm64.tar linknest-runtime:bookworm-arm64
python scripts/release-image.py runtime-lock
```

`runtime-lock` 检查所有层，发现任一历史层包含 LinkNest 程序或许可目录即拒绝；随后记录运行环境归档的 SHA-256。每次 `prepare` 都重新检查内容和锁定哈希，防止误把旧应用镜像当作基础。首次精简发布使用经核对的原有 Debian 与依赖层初始化纯运行环境归档，完全排除旧程序层；以后发布不读取旧应用镜像。

以已提交、干净的独立源码工作树编译 ARM64 程序，把结果放到发布暂存目录。以下为类 Unix shell 示例：

```sh
source_dir="$PWD/.tools/release-1.1.5-clean/source"
stage_dir="$PWD/.tools/release-1.1.5-clean"
cd "$source_dir"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$stage_dir/linknest" ./cmd/linknest
cd -
python scripts/release-image.py prepare --version 1.1.5 --source "$source_dir" --stage "$stage_dir"
```

脚本读取本地 Go SDK 与模块缓存中的依赖许可证，以及工作树中的第三方说明；所有文件缺失均会停止。生成镜像只增加一层当前程序与许可证，运行环境层保持原样，后续发布不会逐版累积。`Dockerfile.runtime` 也以独立的 `linknest-runtime:bookworm-arm64` 为默认基础，用于有 Docker 的环境。

镜像顶层 `created`、当前程序层历史与 `org.opencontainers.image.created` 使用同一个 UTC 时间，默认取源码提交时间；可用非负 Unix 秒值 `SOURCE_DATE_EPOCH` 显式覆盖。这样既保留可重现的构建，也能让 Docker 正确显示镜像日期；`TZ=Asia/Shanghai` 只影响容器内时区，不能补全镜像创建时间。

`release.json` 记录源码提交、创建时间、程序与镜像哈希、运行环境哈希和层数。发布通过本地 `.tools/registry/crane.exe` 完成，令牌从 `local/dockerhub-token.txt` 读取，经标准输入登录；可用 `HTTP_PROXY` / `HTTPS_PROXY` 指定代理：

```sh
python scripts/release-image.py publish --version 1.1.5 --source "$source_dir" --stage "$stage_dir"
python scripts/release-image.py artifacts --version 1.1.5 --source "$source_dir" --stage "$stage_dir"
```

推送前核对归档哈希；推送后核对远端完整配置和层摘要，再将 `latest` 指向同一摘要。离线镜像与源码 ZIP 输出到 `dist/`。源码归档来自 Git 已提交内容，发布前必须检查索引，确保测试、`local/`、依赖缓存和密钥均未提交。发布成功后删除临时 Docker 登录目录和原始令牌文件。
