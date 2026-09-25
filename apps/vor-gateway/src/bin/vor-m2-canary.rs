// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const ENDPOINT: &str = "http://127.0.0.1:8742/mcp";
const PROTOCOL_VERSION: &str = "2026-07-28";
const BEARER_ENV: &str = "VOR_M2_OAUTH_BEARER";

type AnyError = Box<dyn Error>;

fn main() {
    if let Err(error) = run() {
        eprintln!("vor-m2-canary error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AnyError> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("prepare") => prepare_command(&args[1..]),
        Some("commit") => commit_command(&args[1..]),
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unsupported command: {other}").into()),
    }
}

fn bearer() -> Result<String, AnyError> {
    let value = std::env::var(BEARER_ENV).map_err(|_| format!("{BEARER_ENV} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{BEARER_ENV} is empty").into());
    }
    Ok(value)
}

fn prepare_command(args: &[String]) -> Result<(), AnyError> {
    let mut prepared_out = None::<PathBuf>;
    let mut device = None::<String>;
    let mut cwd = None::<String>;
    let mut argv = Vec::<String>::new();
    let mut timeout_ms = None::<u64>;
    let mut max_output_bytes = None::<usize>;
    let mut columns = None::<u16>;
    let mut rows = None::<u16>;
    let mut expect_capability = None::<String>;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--prepared-out" => prepared_out = Some(next_path(args, &mut index, "--prepared-out")?),
            "--device" => device = Some(next_value(args, &mut index, "--device")?.to_owned()),
            "--cwd" => cwd = Some(next_value(args, &mut index, "--cwd")?.to_owned()),
            "--arg" => argv.push(next_value(args, &mut index, "--arg")?.to_owned()),
            "--timeout-ms" => {
                timeout_ms = Some(next_value(args, &mut index, "--timeout-ms")?.parse()?)
            }
            "--max-output-bytes" => {
                max_output_bytes =
                    Some(next_value(args, &mut index, "--max-output-bytes")?.parse()?)
            }
            "--columns" => columns = Some(next_value(args, &mut index, "--columns")?.parse()?),
            "--rows" => rows = Some(next_value(args, &mut index, "--rows")?.parse()?),
            "--expect-capability" => {
                expect_capability =
                    Some(next_value(args, &mut index, "--expect-capability")?.to_owned())
            }
            other => return Err(format!("unsupported prepare option: {other}").into()),
        }
        index += 1;
    }

    let prepared_out = prepared_out.ok_or("prepare requires --prepared-out")?;
    let device = device.ok_or("prepare requires --device")?;
    let cwd = cwd.ok_or("prepare requires --cwd")?;
    if argv.is_empty() {
        return Err("prepare requires at least one --arg".into());
    }
    if prepared_out.exists() {
        return Err("prepared output already exists; refusing to overwrite".into());
    }

    let token = bearer()?;
    let listed = rpc(&token, "tools/list", None, None, 20)?;
    let tools = listed
        .get("tools")
        .and_then(Value::as_array)
        .ok_or("tools/list did not return tools")?;
    let names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();

    for required in [
        "prepare_terminal",
        "commit_terminal",
        "poll_terminal",
        "cancel_terminal",
    ] {
        if !names.contains(required) {
            return Err(format!("missing required MCP tool: {required}").into());
        }
    }
    for forbidden in [
        "terminal_exec",
        "write_file",
        "process_terminate",
        "browser_use",
    ] {
        if names.contains(forbidden) {
            return Err(format!("unsafe MCP tool exposed: {forbidden}").into());
        }
    }

    let mut arguments = json!({
        "device_id": device,
        "cwd": cwd,
        "argv": argv,
    });
    let object = arguments
        .as_object_mut()
        .ok_or("terminal arguments unavailable")?;
    if let Some(value) = timeout_ms {
        object.insert("timeout_ms".into(), Value::from(value));
    }
    if let Some(value) = max_output_bytes {
        object.insert("max_output_bytes".into(), Value::from(value));
    }
    if let Some(value) = columns {
        object.insert("columns".into(), Value::from(value));
    }
    if let Some(value) = rows {
        object.insert("rows".into(), Value::from(value));
    }

    let prepared = tool_text(rpc(
        &token,
        "tools/call",
        Some("prepare_terminal"),
        Some(arguments.clone()),
        21,
    )?)?;
    if prepared.get("status").and_then(Value::as_str) != Some("approval_required") {
        return Err(format!(
            "prepare_terminal returned unexpected status: {:?}",
            prepared.get("status")
        )
        .into());
    }
    let challenge = prepared
        .get("challenge")
        .ok_or("prepare_terminal missing challenge")?;
    if let Some(expected) = expect_capability.as_deref()
        && challenge.get("required_capability").and_then(Value::as_str) != Some(expected)
    {
        return Err(format!(
            "required_capability mismatch: expected {expected:?}, got {:?}",
            challenge.get("required_capability")
        )
        .into());
    }

    let artifact = json!({
        "device_id": device,
        "cwd": cwd,
        "argv": argv,
        "arguments": arguments,
        "request_base64": prepared.get("request_base64").ok_or("missing request_base64")?,
        "challenge": challenge,
    });
    if let Some(parent) = prepared_out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&prepared_out, serde_json::to_vec_pretty(&artifact)?)?;

    println!(
        "{}",
        json!({
            "phase": "prepared",
            "status": "approval_required",
            "cwd": artifact["cwd"],
            "argv": artifact["argv"],
            "required_capability": artifact["challenge"]["required_capability"],
            "terminal_tools_exposed": [
                "prepare_terminal",
                "commit_terminal",
                "poll_terminal",
                "cancel_terminal"
            ],
            "unsafe_tools_exposed": []
        })
    );
    Ok(())
}

fn commit_command(args: &[String]) -> Result<(), AnyError> {
    let mut prepared_file = None::<PathBuf>;
    let mut approval_file = None::<PathBuf>;
    let mut expected_commit_status = "ok".to_owned();
    let mut expected_final_state = None::<String>;
    let mut expected_output = None::<String>;
    let mut cancel_after_start = false;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--prepared-file" => {
                prepared_file = Some(next_path(args, &mut index, "--prepared-file")?)
            }
            "--approval-file" => {
                approval_file = Some(next_path(args, &mut index, "--approval-file")?)
            }
            "--expect-commit-status" => {
                expected_commit_status =
                    next_value(args, &mut index, "--expect-commit-status")?.to_owned()
            }
            "--expect-final-state" => {
                expected_final_state =
                    Some(next_value(args, &mut index, "--expect-final-state")?.to_owned())
            }
            "--expect-output" => {
                expected_output = Some(next_value(args, &mut index, "--expect-output")?.to_owned())
            }
            "--cancel-after-start" => cancel_after_start = true,
            other => return Err(format!("unsupported commit option: {other}").into()),
        }
        index += 1;
    }

    let prepared_file = prepared_file.ok_or("commit requires --prepared-file")?;
    let approval_file = approval_file.ok_or("commit requires --approval-file")?;
    let token = bearer()?;
    let prepared: Value = serde_json::from_slice(&fs::read(&prepared_file)?)?;
    let approval = fs::read_to_string(&approval_file)?.trim().to_owned();
    if approval.is_empty() {
        return Err("approval file is empty".into());
    }

    let device_id = prepared["device_id"]
        .as_str()
        .ok_or("prepared device_id missing")?;
    let request_base64 = prepared["request_base64"]
        .as_str()
        .ok_or("prepared request missing")?;
    let arguments = json!({
        "device_id": device_id,
        "request_base64": request_base64,
        "approval_base64": approval,
    });

    let committed = tool_text(rpc(
        &token,
        "tools/call",
        Some("commit_terminal"),
        Some(arguments.clone()),
        22,
    )?)?;
    let commit_status = committed
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if commit_status != expected_commit_status {
        return Err(format!(
            "commit status mismatch: expected {expected_commit_status:?}, got {commit_status:?}"
        )
        .into());
    }

    let replayed = tool_text(rpc(
        &token,
        "tools/call",
        Some("commit_terminal"),
        Some(arguments),
        23,
    )?)?;
    if replayed.get("status").and_then(Value::as_str) != Some("approval_replayed") {
        return Err(format!(
            "replay returned unexpected status: {:?}",
            replayed.get("status")
        )
        .into());
    }

    if commit_status != "ok" {
        println!(
            "{}",
            json!({
                "live_m2": "PASS",
                "commit": commit_status,
                "replay": "approval_replayed",
                "session": null
            })
        );
        return Ok(());
    }

    let data = committed.get("data").ok_or("commit data missing")?;
    let session_id = data
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or("commit session_id missing")?;

    if cancel_after_start {
        let cancelled = tool_text(rpc(
            &token,
            "tools/call",
            Some("cancel_terminal"),
            Some(json!({
                "device_id": device_id,
                "session_id": session_id,
            })),
            24,
        )?)?;
        if cancelled.get("status").and_then(Value::as_str) != Some("ok")
            || cancelled["data"]["cancel_requested"] != Value::Bool(true)
        {
            return Err(format!("cancel_terminal failed: {cancelled}").into());
        }
    }

    let final_payload = poll_until_finished(&token, device_id, session_id)?;
    if let Some(expected) = expected_final_state.as_deref()
        && final_payload.get("state").and_then(Value::as_str) != Some(expected)
    {
        return Err(format!(
            "final state mismatch: expected {expected:?}, got {:?}",
            final_payload.get("state")
        )
        .into());
    }
    if let Some(needle) = expected_output.as_deref() {
        let bytes = STANDARD.decode(
            final_payload["output_base64"]
                .as_str()
                .ok_or("final output_base64 missing")?
                .as_bytes(),
        )?;
        if !bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            return Err(format!(
                "terminal output did not contain expected text {needle:?}: {}",
                String::from_utf8_lossy(&bytes)
            )
            .into());
        }
    }

    println!(
        "{}",
        json!({
            "live_m2": "PASS",
            "commit": "ok",
            "replay": "approval_replayed",
            "session_id": session_id,
            "final_state": final_payload["state"],
            "exit_code": final_payload["exit_code"],
            "error_code": final_payload["error_code"],
        })
    );
    Ok(())
}

fn poll_until_finished(token: &str, device_id: &str, session_id: &str) -> Result<Value, AnyError> {
    for index in 0..500u64 {
        let polled = tool_text(rpc(
            token,
            "tools/call",
            Some("poll_terminal"),
            Some(json!({
                "device_id": device_id,
                "session_id": session_id,
            })),
            100 + index,
        )?)?;
        if polled.get("status").and_then(Value::as_str) != Some("ok") {
            return Err(format!("poll_terminal failed: {polled}").into());
        }
        let data = polled.get("data").ok_or("poll data missing")?;
        if data.get("state").and_then(Value::as_str) != Some("running") {
            return Ok(data.clone());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("terminal session did not finish within canary poll budget".into())
}

fn rpc(
    token: &str,
    method: &str,
    name: Option<&str>,
    arguments: Option<Value>,
    request_id: u64,
) -> Result<Value, AnyError> {
    let mut params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "vor-m2-live-canary",
                "version": "1.0"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    });
    if method == "tools/call" {
        let object = params.as_object_mut().ok_or("params object unavailable")?;
        object.insert(
            "name".into(),
            Value::String(name.ok_or("tool name missing")?.to_owned()),
        );
        object.insert("arguments".into(), arguments.unwrap_or_else(|| json!({})));
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    });

    let auth = format!("Bearer {token}");
    let mut request = ureq::post(ENDPOINT)
        .header("Authorization", &auth)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", PROTOCOL_VERSION)
        .header("Mcp-Method", method)
        .header("Content-Type", "application/json");
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }
    let mut response = request.send_json(&payload)?;
    let text = response.body_mut().read_to_string()?;
    let rpc = decode_rpc_payload(&text)?;
    if rpc.get("error").is_some() {
        return Err("MCP returned an error".into());
    }
    rpc.get("result")
        .cloned()
        .ok_or_else(|| "MCP result is missing".into())
}

fn decode_rpc_payload(input: &str) -> Result<Value, AnyError> {
    let trimmed = input.trim();
    if trimmed.starts_with('{') {
        return Ok(serde_json::from_str(trimmed)?);
    }
    let mut last = None;
    for line in trimmed.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data) {
            last = Some(value);
        }
    }
    last.ok_or_else(|| "MCP response contained no JSON payload".into())
}

fn tool_text(result: Value) -> Result<Value, AnyError> {
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .ok_or("MCP tool text result is missing")?;
    Ok(serde_json::from_str(content)?)
}

fn next_value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, AnyError> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}").into())
}

fn next_path(args: &[String], index: &mut usize, flag: &str) -> Result<PathBuf, AnyError> {
    Ok(PathBuf::from(next_value(args, index, flag)?))
}

fn print_help() {
    println!("Vör M2 live canary helper");
    println!(
        "  vor-m2-canary prepare --prepared-out FILE --device ID --cwd PATH --arg VALUE [--arg VALUE ...] [--timeout-ms N] [--max-output-bytes N] [--expect-capability CAP]"
    );
    println!(
        "  vor-m2-canary commit --prepared-file FILE --approval-file FILE [--expect-commit-status STATUS] [--expect-final-state STATE] [--expect-output TEXT] [--cancel-after-start]"
    );
    println!("Bearer is read only from VOR_M2_OAUTH_BEARER and is never printed.");
}
