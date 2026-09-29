from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO = Path(__file__).resolve().parents[2]
LOCAL_STATE = REPO / "state" / "local"
ENDPOINT = "https://mcp.vorcommander.app/mcp"
PROTOCOL_VERSION = "2026-07-28"
OAUTH_ENV = "VOR_M1_OAUTH_BEARER"


def oauth_bearer() -> str:
    bearer = os.environ.get(OAUTH_ENV, "").strip()
    if not bearer:
        raise RuntimeError(
            f"{OAUTH_ENV} is required. Use an OAuth-authorized MCP access token; "
            "local vor-gateway grants are not valid against the public VPS GrantStore."
        )
    return bearer


def decode_mcp_payload(text: str) -> dict:
    stripped = text.strip()
    if stripped.startswith("{"):
        payload = json.loads(stripped)
        if not isinstance(payload, dict):
            raise RuntimeError("MCP response is not an object")
        return payload

    payloads: list[dict] = []
    for line in stripped.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            item = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            payloads.append(item)
    if not payloads:
        raise RuntimeError("MCP response contained no JSON payload")
    return payloads[-1]


def mcp_call(
    bearer: str,
    method: str,
    *,
    name: str | None = None,
    arguments: dict | None = None,
    request_id: int,
) -> dict:
    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
        "Content-Type": "application/json",
    }
    if name:
        headers["Mcp-Name"] = name

    params: dict = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "vor-m1-live-canary-python",
                "version": "1.0",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    if method == "tools/call":
        params.update({"name": name, "arguments": arguments or {}})

    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(ENDPOINT, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024)
    except HTTPError as exc:
        raise RuntimeError(f"MCP HTTP {exc.code}") from None
    except (URLError, OSError, TimeoutError) as exc:
        raise RuntimeError(f"MCP transport failed: {type(exc).__name__}") from None

    payload = decode_mcp_payload(raw.decode("utf-8"))
    error = payload.get("error")
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        raise RuntimeError(f"MCP returned error code {code!r}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MCP result is missing")
    return result


def tool_text(result: dict) -> dict:
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError("MCP tool returned no content")
    first = content[0]
    if not isinstance(first, dict) or not isinstance(first.get("text"), str):
        raise RuntimeError("MCP tool text result is missing")
    payload = json.loads(first["text"])
    if not isinstance(payload, dict):
        raise RuntimeError("MCP tool text is not an object")
    return payload


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    config = json.loads((LOCAL_STATE / "config.json").read_text(encoding="utf-8-sig"))
    device_id = str(config["device_id"])
    bearer = oauth_bearer()

    canary_root = LOCAL_STATE / "m1-canary"
    run_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = canary_root / f"run-python-{run_stamp}"
    target = canary_root / "live-write.txt"
    run_dir.mkdir(parents=True, exist_ok=False)

    try:
        listed = mcp_call(bearer, "tools/list", request_id=10)
        tools = listed.get("tools")
        if not isinstance(tools, list):
            raise RuntimeError("tools/list did not return tools")
        names = {
            item["name"]
            for item in tools
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        required = {"prepare_write", "commit_write"}
        forbidden = {"terminal_exec", "write_file", "process_terminate"}
        if missing := required - names:
            raise RuntimeError(f"missing required MCP tools: {sorted(missing)}")
        if exposed := forbidden & names:
            raise RuntimeError(f"unsafe MCP tools exposed: {sorted(exposed)}")

        content = f"VOR_M1_CANARY {datetime.now(UTC).isoformat()}\n"
        content_bytes = content.encode("utf-8")
        expected_target_sha256 = sha256_file(target) if target.is_file() else "absent"

        prepared = tool_text(
            mcp_call(
                bearer,
                "tools/call",
                name="prepare_write",
                arguments={
                    "device_id": device_id,
                    "path": str(target),
                    "content_base64": base64.b64encode(content_bytes).decode("ascii"),
                    "expected_target_sha256": expected_target_sha256,
                },
                request_id=11,
            )
        )
        if prepared.get("status") != "approval_required":
            raise RuntimeError(f"prepare_write status={prepared.get('status')!r}")

        request_path = run_dir / "request.b64"
        challenge_path = run_dir / "challenge.json"
        approval_path = run_dir / "approval.b64"
        request_path.write_text(str(prepared["request_base64"]), encoding="utf-8")
        challenge_path.write_text(
            json.dumps(prepared["challenge"], separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["VOR_APPROVER_SECRET_STORE"] = str(LOCAL_STATE / "approval-secrets")
        signed = subprocess.run(
            [
                str(REPO / "target" / "release" / "vor-approver.exe"),
                "sign",
                "--approver-id",
                "owner-local",
                "--request-file",
                str(request_path),
                "--challenge-file",
                str(challenge_path),
                "--out",
                str(approval_path),
            ],
            cwd=REPO,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
            check=False,
        )
        if signed.returncode != 0:
            raise RuntimeError(f"vor-approver exited with code {signed.returncode}")

        approval_base64 = approval_path.read_text(encoding="utf-8").strip()
        committed = tool_text(
            mcp_call(
                bearer,
                "tools/call",
                name="commit_write",
                arguments={
                    "device_id": device_id,
                    "request_base64": str(prepared["request_base64"]),
                    "approval_base64": approval_base64,
                },
                request_id=12,
            )
        )
        if committed.get("status") != "ok":
            raise RuntimeError(f"commit_write status={committed.get('status')!r}")
        if target.read_text(encoding="utf-8") != content:
            raise RuntimeError("committed file content mismatch")

        replayed = tool_text(
            mcp_call(
                bearer,
                "tools/call",
                name="commit_write",
                arguments={
                    "device_id": device_id,
                    "request_base64": str(prepared["request_base64"]),
                    "approval_base64": approval_base64,
                },
                request_id=13,
            )
        )
        if replayed.get("status") != "approval_replayed":
            raise RuntimeError(f"replay status={replayed.get('status')!r}")

        print(
            json.dumps(
                {
                    "live_m1": "PASS",
                    "device": device_id,
                    "prepare": prepared.get("status"),
                    "commit": committed.get("status"),
                    "replay": replayed.get("status"),
                    "target": str(target),
                    "content_sha256": prepared.get("content_sha256"),
                    "direct_write_tool_exposed": "write_file" in names,
                    "terminal_tool_exposed": "terminal_exec" in names,
                    "process_terminate_tool_exposed": "process_terminate" in names,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        bearer = ""


if __name__ == "__main__":
    raise SystemExit(main())
