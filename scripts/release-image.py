"""Build and publish LinkNest from a locked application-free runtime archive.

The runtime archive is built independently with Dockerfile.runtime-base. Every
prepare operation validates all runtime layers, then adds exactly one layer with
the current binary and licenses. Previous application releases are never bases.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
REPO = "jacoyyyy/linknest"
BINARY_PATH = "usr/local/bin/linknest"
DOCS_PATH = "usr/share/doc/linknest"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_config(archive):
    manifests = json.load(archive.extractfile("manifest.json"))
    if len(manifests) != 1:
        raise ValueError("Exactly one platform is required")
    manifest = manifests[0]
    config = json.load(archive.extractfile(manifest["Config"]))
    return manifest, config


def validate_runtime(path):
    with tarfile.open(path) as archive:
        manifest, config = archive_config(archive)
        if config["os"] != "linux" or config["architecture"] != "arm64":
            raise ValueError("Runtime must be Linux ARM64")
        if len(manifest["Layers"]) != len(config["rootfs"]["diff_ids"]):
            raise ValueError("Runtime layer count mismatch")
        settings = config.get("config", {})
        if settings.get("Labels", {}).get("org.linknest.runtime.kind") != "debian-minimal-v1" or len(manifest["Layers"]) != 1:
            raise ValueError("Expected the single-layer minimal runtime built by minimal-runtime.py or Dockerfile.runtime-base")
        if any(item.startswith("LINKNEST_") for item in settings.get("Env", [])) or BINARY_PATH in " ".join(settings.get("Entrypoint") or []):
            raise ValueError("Runtime contains application configuration")
        for name in manifest["Layers"]:
            with tarfile.open(fileobj=archive.extractfile(name), mode="r:*") as layer:
                for member in layer:
                    p = PurePosixPath(member.name)
                    if p.is_absolute() or ".." in p.parts:
                        raise ValueError("Unsafe runtime layer path")
                    item = str(p)
                    if item == BINARY_PATH or item == DOCS_PATH or item.startswith(DOCS_PATH + "/"):
                        raise ValueError("Runtime has a LinkNest application layer; refusing cumulative releases")
                    if item in {"usr/bin/apt", "usr/bin/apt-get", "usr/bin/perl", "usr/bin/python3"}:
                        raise ValueError("Runtime was not trimmed; refusing a full Debian environment")
        return manifest, config


def run(args, env=None, data=None):
    result = subprocess.run([str(arg) for arg in args], input=data, capture_output=True, env=env)
    if result.returncode:
        # Credentials are supplied through stdin only, never command arguments.
        raise RuntimeError(result.stderr.decode(errors="replace")[-2000:])
    return result.stdout


def license_files(source):
    modules = ROOT / ".tools/cache/go/pkg/mod"
    return {
        "GO-LICENSE": ROOT / ".tools/go/LICENSE",
        "XCRYPTO-LICENSE": modules / "golang.org/x/crypto@v0.48.0/LICENSE",
        "XSYS-LICENSE": modules / "golang.org/x/sys@v0.41.0/LICENSE",
        "WEBSOCKET-LICENSE": modules / "github.com/gorilla/websocket@v1.5.3/LICENSE",
        "QRCODE-LICENSE": modules / "github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e/LICENSE",
        "XTERM-LICENSE": source / "web/vendor/LICENSE",
        "THIRD_PARTY.md": source / "THIRD_PARTY.md",
    }


def prepare(args):
    runtime_lock = json.loads(args.runtime_base.with_suffix(".json").read_text(encoding="utf8"))
    runtime_sha = sha(args.runtime_base.read_bytes())
    if runtime_lock["archiveSHA256"] != runtime_sha:
        raise ValueError("Runtime archive changed; validate and explicitly update its lock first")
    manifest, base_config = validate_runtime(args.runtime_base)
    revision = run(["git", "-c", "safe.directory=" + args.source.as_posix(), "-C", args.source, "rev-parse", "HEAD"]).decode().strip()
    if run(["git", "-c", "safe.directory=" + args.source.as_posix(), "-C", args.source, "status", "--porcelain", "--untracked-files=normal"]).strip():
        raise ValueError("Commit source changes before preparing a release")
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        epoch = run(["git", "-c", "safe.directory=" + args.source.as_posix(), "-C", args.source, "show", "-s", "--format=%ct", "HEAD"]).decode().strip()
    if not epoch.isdecimal():
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp")
    created = datetime.fromtimestamp(int(epoch), timezone.utc).isoformat().replace("+00:00", "Z")
    binary = (args.stage / "linknest").read_bytes()
    if binary[:4] != b"\x7fELF" or binary[4] != 2 or int.from_bytes(binary[18:20], "little") != 183:
        raise ValueError("Expected an ELF64 ARM64 LinkNest binary")
    files = {BINARY_PATH: binary, **{DOCS_PATH + "/" + name: path.read_bytes() for name, path in license_files(args.source).items()}}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as layer:
        for name in ["usr", "usr/local", "usr/local/bin", "usr/share", "usr/share/doc", DOCS_PATH]:
            info = tarfile.TarInfo(name)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            layer.addfile(info)
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o755 if name == BINARY_PATH else 0o644
            layer.addfile(info, io.BytesIO(payload))
    raw_layer = raw.getvalue()
    layer_bytes = gzip.compress(raw_layer, compresslevel=6, mtime=0)
    layer_name = sha(layer_bytes) + ".tar.gz"
    config = {key: copy.deepcopy(base_config[key]) for key in ["os", "architecture", "rootfs", "history"]}
    config["created"] = created
    config["rootfs"]["diff_ids"].append("sha256:" + sha(raw_layer))
    config["history"].append({"created": created, "created_by": "COPY current LinkNest binary and licenses onto locked runtime"})
    config["config"] = {
        "Entrypoint": ["/usr/local/bin/linknest"],
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LINKNEST_DATA_DIR=/data", "LINKNEST_ADMIN_ADDR=127.0.0.1:17880", "LINKNEST_FIREWALL=disabled", "GOMEMLIMIT=128MiB", "GOMAXPROCS=2", "TZ=Asia/Shanghai"],
        "Labels": {"org.opencontainers.image.created": created, "org.opencontainers.image.version": args.version, "org.opencontainers.image.source": "https://github.com/daixu0502/linknest", "org.opencontainers.image.revision": revision},
        "Volumes": {"/data": {}}, "ExposedPorts": {"17880/tcp": {}}, "StopSignal": "SIGTERM",
        "Healthcheck": {"Test": ["CMD", "linknest", "healthcheck"], "Interval": 30000000000, "Timeout": 5000000000, "StartPeriod": 10000000000, "Retries": 3},
    }
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    config_name = sha(config_bytes) + ".json"
    layers = manifest["Layers"] + [layer_name]
    image_manifest = [{"Config": config_name, "RepoTags": [REPO + ":" + args.version], "Layers": layers}]
    temporary = args.stage / "image.tar.tmp"
    with tarfile.open(args.runtime_base) as runtime, tarfile.open(temporary, "w") as out:
        for name in manifest["Layers"]:
            out.addfile(runtime.getmember(name), runtime.extractfile(name))
        for name, payload in [(layer_name, layer_bytes), (config_name, config_bytes), ("manifest.json", json.dumps(image_manifest).encode())]:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(payload), 0o644
            out.addfile(info, io.BytesIO(payload))
    temporary.replace(args.stage / "image.tar")
    with tarfile.open(args.stage / "image.tar") as image:
        actual, settings = archive_config(image)
        if settings != config or actual["Layers"] != layers:
            raise ValueError("Output archive configuration mismatch")
        with tarfile.open(fileobj=image.extractfile(layer_name)) as layer:
            actual_files = {member.name: layer.extractfile(member).read() for member in layer if member.isfile()}
            if actual_files != files:
                raise ValueError("Output application layer mismatch")
        compressed_size = sum(image.getmember(name).size for name in layers)
    metadata = dict(version=args.version, revision=revision, created=created, architecture="linux/arm64", binarySHA256=sha(binary), runtimeArchiveSHA256=runtime_sha, runtimeLayers=len(manifest["Layers"]), applicationLayers=1, layers=len(layers), compressedLayerBytes=compressed_size, imageBytes=(args.stage / "image.tar").stat().st_size, imageSHA256=sha((args.stage / "image.tar").read_bytes()))
    (args.stage / "release.json").write_text(json.dumps(metadata, indent=2), encoding="utf8")
    return metadata


def publish(args):
    metadata = json.loads((args.stage / "release.json").read_text(encoding="utf8"))
    if metadata["version"] != args.version or sha((args.stage / "image.tar").read_bytes()) != metadata["imageSHA256"]:
        raise ValueError("Release version or archive changed; run prepare again")
    with tarfile.open(args.stage / "image.tar") as image:
        _, expected_config = archive_config(image)
    env = dict(os.environ, DOCKER_CONFIG=str(args.stage / "auth"))
    crane = ROOT / ".tools/registry/crane.exe"
    token = (ROOT / "local/dockerhub-token.txt").read_text(encoding="utf8").strip()
    run([crane, "auth", "login", "docker.io", "-u", "jacoyyyy", "--password-stdin"], env, (token + "\n").encode())
    del token
    def tool(*values):
        return run([crane, *values], env)
    tag = REPO + ":" + args.version
    tool("push", args.stage / "image.tar", tag)
    digest = tool("digest", tag).decode().strip()
    remote = json.loads(tool("config", REPO + "@" + digest))
    if remote != expected_config:
        raise ValueError("Published configuration or layer digests do not match the prepared image")
    tool("tag", REPO + "@" + digest, "latest")
    if tool("digest", REPO + ":latest").decode().strip() != digest:
        raise ValueError("latest does not match version tag")
    metadata["digest"] = digest
    (args.stage / "release.json").write_text(json.dumps(metadata, indent=2), encoding="utf8")
    return metadata


def artifacts(args):
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    prefix = "linknest-" + args.version
    run(["git", "-c", "safe.directory=" + args.source.as_posix(), "-C", args.source, "archive", "--format=zip", "--prefix=" + prefix + "/", "-o", dist / (prefix + "-source.zip"), "HEAD"])
    with (args.stage / "image.tar").open("rb") as source, gzip.open(dist / (prefix + "-linux-arm64.tar.gz"), "wb", compresslevel=6) as target:
        shutil.copyfileobj(source, target)
    return [dict(file=name, bytes=(dist / name).stat().st_size, sha256=sha((dist / name).read_bytes())) for name in [prefix + "-source.zip", prefix + "-linux-arm64.tar.gz"]]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["runtime-lock", "prepare", "publish", "artifacts"])
    parser.add_argument("--version", default="1.1.5")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--runtime-base", type=Path, default=ROOT / ".tools/runtime-base/minimal-bookworm-arm64.tar")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-a-zA-Z0-9.]+)?", args.version):
        parser.error("Invalid release version")
    args.source = args.source.resolve()
    args.stage = (args.stage or ROOT / (".tools/release-" + args.version)).resolve()
    args.stage.mkdir(parents=True, exist_ok=True)
    if args.mode == "runtime-lock":
        manifest, config = validate_runtime(args.runtime_base)
        result = dict(archiveSHA256=sha(args.runtime_base.read_bytes()), architecture="linux/arm64", layers=len(manifest["Layers"]), applicationFree=True)
        args.runtime_base.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf8")
    else:
        result = {"prepare": prepare, "publish": publish, "artifacts": artifacts}[args.mode](args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
