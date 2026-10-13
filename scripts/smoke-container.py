#!/usr/bin/env python3
"""Disposable localhost container smoke test. Never targets an unlabeled container."""
import http.cookiejar
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

docker = os.environ.get("DOCKER_BIN", "docker")
name = sys.argv[1] if len(sys.argv) > 1 else "linknest-test"
info = json.loads(subprocess.check_output([docker, "inspect", name]))[0]
assert info["Config"]["Labels"].get("linknest.test") == "true", "Not a labeled disposable test container"
assert "ALL" in info["HostConfig"]["CapDrop"] and not info["HostConfig"]["CapAdd"], "Unexpected capabilities"
assert info["HostConfig"]["Privileged"] is False
assert info["HostConfig"]["PortBindings"]["17880/tcp"][0]["HostIp"] == "127.0.0.1"
binding = info["HostConfig"]["PortBindings"]["17880/tcp"][0]
base = "http://127.0.0.1:" + binding["HostPort"] + "/api/"
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))

def call(path, method="GET", data=None):
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(base + path, data=body, method=method,
        headers={"Content-Type": "application/json", "X-LinkNest-Request": "1"})
    with client.open(request, timeout=20) as response:
        return json.load(response)

assert call("health")["initialized"] is False, "Test requires a fresh data volume"
try:
    call("state")
    raise AssertionError("Unauthenticated request succeeded")
except urllib.error.HTTPError as error:
    assert error.code == 401

bootstrap = subprocess.check_output([docker, "exec", name, "cat", "/data/bootstrap.token"]).decode().strip()
password = secrets.token_urlsafe(24)
call("setup", "POST", {"token": bootstrap, "username": "admin", "password": password})
call("login", "POST", {"username": "admin", "password": password})
state = call("state")
assert state["version"] == "1.0.0"
assert state["config"]["schema"] == 4
assert state["config"]["access"]["autoBan"]["enabled"] is False
assert state["firewall"]["enabled"] is False
config = state["config"]
config["rules"] = [
    {"id": "test-http", "name": "Local HTTP smoke", "kind": "web", "enabled": True,
     "listen": "127.0.0.1:18080", "target": "http://127.0.0.1:17880", "openFirewall": False},
    {"id": "test-tcp", "name": "Local TCP smoke", "kind": "tcp", "enabled": True,
     "listen": "127.0.0.1:18082", "target": "127.0.0.1:17880", "openFirewall": False},
]
call("config", "PUT", config)
running = call("state")
assert all(x["state"] == "running" for x in running["rules"])
assert len(running["config"]["rules"][0]["routes"]) == 1, "Legacy web rule was not migrated"
for asset in ("workflows.js", "portal.css", "portal.js", "certificates.js", "navigation.js", "security.js"):
    with client.open(base.replace("/api/", "/") + asset, timeout=10) as response:
        assert response.status == 200 and len(response.read()) > 100
for port in (17880, 18080, 18082):
    subprocess.check_call([docker, "exec", "-e", "LINKNEST_ADMIN_ADDR=127.0.0.1:"+str(port), name, "linknest", "healthcheck"])
config["rules"] = []
call("config", "PUT", config)
assert call("state")["rules"] == []
call("logout", "POST", {})
assert call("health")["authenticated"] is False
print(json.dumps({"ok": True, "checks": ["localhost binding", "no capabilities", "bootstrap", "login", "schema 4", "legacy migration", "new UI assets", "firewall off", "HTTP proxy", "TCP tunnel", "stop rules", "logout"]}))
