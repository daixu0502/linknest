"""Keep a dependency-closed Debian runtime, never a previous LinkNest image.

Accept either a pure runtime Docker archive (offline releases) or an independent
Debian dependency stage (Docker builds). Keep legacy IPv4/IPv6 NAT, all xtables
plugins, CA certificates, timezones, shell, NSS data and distribution licenses.
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
import posixpath
import stat
import struct
import tarfile

KIND = "debian-minimal-v1"
LABEL = "org.linknest.runtime.kind"
APP = "usr/local/bin/linknest"
DOCS = "usr/share/doc/linknest"
MACHINES = {183: ("arm64", "aarch64-linux-gnu"), 62: ("amd64", "x86_64-linux-gnu"), 40: ("arm", "arm-linux-gnueabihf"), 3: ("386", "i386-linux-gnu"), 21: ("ppc64le", "powerpc64le-linux-gnu"), 22: ("s390x", "s390x-linux-gnu"), 243: ("riscv64", "riscv64-linux-gnu")}


def clean(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("Unsafe runtime archive path: " + name)
    return str(p)


def application_path(name):
    return name == APP or name == DOCS or name.startswith(DOCS + "/")


class Source:
    def __init__(self, archive=None, rootfs=None):
        self.entries = {}
        self.rootfs = rootfs
        if archive:
            with tarfile.open(archive) as image:
                manifests = json.load(image.extractfile("manifest.json"))
                if len(manifests) != 1:
                    raise ValueError("Exactly one runtime platform is required")
                manifest = manifests[0]
                config = json.load(image.extractfile(manifest["Config"]))
                settings = config.get("config", {})
                if config["os"] != "linux" or any(v.startswith("LINKNEST_") for v in settings.get("Env", [])) or "linknest" in " ".join(settings.get("Entrypoint") or []):
                    raise ValueError("Expected a pure Linux dependency image, not a LinkNest release")
                for layer_name in manifest["Layers"]:
                    with tarfile.open(fileobj=image.extractfile(layer_name)) as layer:
                        for member in layer:
                            name = clean(member.name)
                            if application_path(name):
                                raise ValueError("Historical LinkNest application layer is forbidden")
                            parent, _, base = name.rpartition("/")
                            if base.startswith(".wh."):
                                target = parent if base == ".wh..wh..opq" else posixpath.join(parent, base[4:])
                                for old in list(self.entries):
                                    if old.startswith(target + "/") or (old == target and base != ".wh..wh..opq"):
                                        del self.entries[old]
                                continue
                            if not member.isdir():
                                for old in list(self.entries):
                                    if old.startswith(name + "/"):
                                        del self.entries[old]
                            self.entries[name] = (copy.copy(member), layer.extractfile(member).read() if member.isfile() else None)
        else:
            with tarfile.open(fileobj=io.BytesIO(), mode="w") as metadata:
                for directory, dirs, files in os.walk(rootfs, followlinks=False):
                    if Path(directory) == rootfs:
                        dirs[:] = [n for n in dirs if n not in {"dev", "proc", "sys", "tmp", "run", "out"}]
                    for child in [*dirs, *files]:
                        path = Path(directory) / child
                        name = path.relative_to(rootfs).as_posix()
                        if application_path(name):
                            raise ValueError("Dependency stage already contains LinkNest")
                        member = metadata.gettarinfo(str(path), arcname=name)
                        if member.isfile() or member.isdir() or member.issym() or member.islnk():
                            self.entries[name] = (member, None)

    def data(self, name):
        return (self.rootfs / name).read_bytes() if self.rootfs else self.entries[name][1]


def elf_dependencies(data):
    if data[:4] != b"\x7fELF":
        return [], None, None
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("Unsupported ELF encoding")
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    wide = data[4] == 2
    offset = struct.unpack_from(endian + ("Q" if wide else "I"), data, 32 if wide else 28)[0]
    size, count = struct.unpack_from(endian + "HH", data, 54 if wide else 42)
    segments = [struct.unpack_from(endian + ("IIQQQQQQ" if wide else "IIIIIIII"), data, offset + i * size) for i in range(count)]
    if not wide:
        segments = [(s[0], s[6], s[1], s[2], s[3], s[4], s[5], s[7]) for s in segments]
    interp = next((data[s[2]:s[2] + s[5]].rstrip(b"\0").decode() for s in segments if s[0] == 3), None)
    dynamic = next((s for s in segments if s[0] == 2), None)
    if dynamic is None:
        return [], interp, machine
    tags = [struct.unpack_from(endian + ("QQ" if wide else "II"), data, p) for p in range(dynamic[2], dynamic[2] + dynamic[5], 16 if wide else 8)]
    strings = next((value for tag, value in tags if tag == 5), None)
    if strings is None:
        return [], interp, machine
    segment = next(s for s in segments if s[0] == 1 and s[3] <= strings < s[3] + s[5])
    table = segment[2] + strings - segment[3]
    return [data[table + value:].split(b"\0", 1)[0].decode() for tag, value in tags if tag == 1], interp, machine


class Runtime:
    def __init__(self, source):
        self.source, self.selected, self.processed = source, set(), set()
        binary = self.resolve("usr/sbin/xtables-legacy-multi")
        machine = elf_dependencies(source.data(binary))[2]
        if machine not in MACHINES:
            raise ValueError("Unsupported runtime architecture")
        self.architecture, self.triplet = MACHINES[machine]
        self.machine = machine

    def resolve(self, name, depth=0):
        if depth > 30:
            raise ValueError("Runtime symlink loop")
        name = posixpath.normpath("/" + name).lstrip("/")
        parts = name.split("/")
        for i in range(len(parts)):
            parent = "/".join(parts[:i + 1])
            member, _ = self.source.entries[parent]
            self.selected.add(parent)
            if member.issym() or member.islnk():
                target = member.linkname if member.islnk() or member.linkname.startswith("/") else posixpath.join(posixpath.dirname(parent), member.linkname)
                return self.resolve(posixpath.join(target, *parts[i + 1:]), depth + 1)
        return name

    def include(self, name):
        name = self.resolve(name)
        if name in self.processed:
            return
        self.processed.add(name)
        if not self.source.entries[name][0].isfile():
            return
        needed, interp, machine = elf_dependencies(self.source.data(name))
        if machine is not None and machine != self.machine:
            raise ValueError("Mixed runtime architectures")
        if interp:
            self.include(interp)
        for library in needed:
            for directory in ["lib/" + self.triplet, "usr/lib/" + self.triplet, "lib", "usr/lib"]:
                try:
                    resolved = self.resolve(directory + "/" + library)
                except KeyError:
                    continue
                self.include(resolved)
                break
            else:
                raise ValueError("Unresolved ELF dependency: " + library + " needed by " + name)

    def collect(self):
        for name in ["usr/sbin/iptables-legacy", "usr/sbin/ip6tables-legacy", "usr/sbin/iptables-legacy-restore", "usr/sbin/ip6tables-legacy-restore", "usr/sbin/iptables-legacy-save", "usr/sbin/ip6tables-legacy-save", "bin/sh", "usr/bin/cat", "etc/ssl/certs/ca-certificates.crt", "etc/nsswitch.conf", "etc/protocols", "etc/services", "etc/passwd", "etc/group", "etc/os-release", "etc/debian_version"]:
            self.include(name)
        for name in self.source.entries:
            if name.startswith(("usr/lib/" + self.triplet + "/xtables/", "usr/share/zoneinfo/")) or name.startswith("usr/share/doc/") and name.endswith("/copyright"):
                self.include(name)
        for name in ["usr/lib/" + self.triplet + "/libnss_dns.so.2", "usr/lib/" + self.triplet + "/libnss_files.so.2", "etc/localtime", "etc/timezone"]:
            if name in self.source.entries:
                self.include(name)
        if any(application_path(name) for name in self.selected):
            raise ValueError("Application entered runtime selection")

    def members(self):
        def order(name):
            member = self.source.entries[name][0]
            return (0 if member.isdir() else 3 if member.islnk() else 2 if member.issym() else 1, name.count("/"), name)
        for name in sorted(self.selected, key=order):
            member = copy.copy(self.source.entries[name][0])
            member.name = name
            if member.islnk():
                member.linkname = self.resolve(member.linkname)
            yield member, self.source.data(name) if member.isfile() else None
        for name, mode in [("tmp", 0o1777), ("run", 0o755), ("data", 0o755)]:
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, mode
            yield member, None

    def write_directory(self, destination):
        destination.mkdir(parents=True, exist_ok=False)
        for member, data in self.members():
            path = destination / member.name
            if member.isdir():
                path.mkdir(exist_ok=True)
            elif member.issym():
                path.symlink_to(member.linkname)
            elif member.islnk():
                os.link(destination / member.linkname, path)
            else:
                path.write_bytes(data)
            if not member.issym():
                os.chmod(path, stat.S_IMODE(member.mode))

    def write_archive(self, output, tag):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as layer:
            for member, data in self.members():
                layer.addfile(member, io.BytesIO(data) if data is not None else None)
        payload = raw.getvalue()
        compressed = gzip.compress(payload, compresslevel=6, mtime=0)
        digest = lambda value: hashlib.sha256(value).hexdigest()
        created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        config = {"os": "linux", "architecture": self.architecture, "created": created, "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"], "Cmd": ["/bin/sh"], "Labels": {LABEL: KIND}}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(payload)]}, "history": [{"created": created, "created_by": "COPY dependency-closed Debian minimal runtime"}]}
        config_bytes = json.dumps(config, separators=(",", ":")).encode()
        config_name, layer_name = digest(config_bytes) + ".json", digest(compressed) + ".tar.gz"
        manifest = [{"Config": config_name, "RepoTags": [tag], "Layers": [layer_name]}]
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        with tarfile.open(temporary, "w") as archive:
            for name, data in [(config_name, config_bytes), (layer_name, compressed), ("manifest.json", json.dumps(manifest).encode())]:
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), 0o644
                archive.addfile(member, io.BytesIO(data))
        temporary.replace(output)
        return {"runtimeKind": KIND, "architecture": self.architecture, "entries": len(self.selected), "compressedLayerBytes": len(compressed), "uncompressedLayerBytes": len(payload)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input", type=Path, help="Application-free Docker runtime archive")
    inputs.add_argument("--rootfs", type=Path, help="Independent dependency stage root")
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output", type=Path, help="Minimal runtime Docker archive")
    outputs.add_argument("--destination", type=Path, help="New directory for Docker scratch stage")
    parser.add_argument("--tag", default="linknest-runtime:minimal-bookworm-arm64")
    args = parser.parse_args()
    source = Source(args.input, args.rootfs.resolve() if args.rootfs else None)
    runtime = Runtime(source)
    runtime.collect()
    if args.output:
        print(json.dumps(runtime.write_archive(args.output, args.tag), indent=2))
    else:
        runtime.write_directory(args.destination)
        print(json.dumps({"runtimeKind": KIND, "architecture": runtime.architecture, "entries": len(runtime.selected)}, indent=2))
