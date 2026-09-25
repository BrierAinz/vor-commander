// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const ENDPOINT: &str = "http://127.0.0.1:8742/mcp";
const PROTOCOL_VERSION: &str = "2026-07-28";

type AnyError = Box<dyn Error>;

fn main() {
    if let Err(error) = run() {
        eprintln!("vor-m1-canary error: {error}");
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

fn prepare_command(args: &[String]) -> Result<(), AnyError> {
    let mut grant_file = None::<PathBuf>;
    let mut prepared_out = None::<PathBuf>;
    let mut device = None::<String>;
    let mut target = None::<String>;
    let mut content = None::<String>;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--grant-file" => grant_file = Some(next_path(args, &mut index, "--grant-file")?),
            "--prepared-out" => prepared_out = Some(next_path(args, &mut index, "--prepared-out")?),
            "--device" => device = Some(next_value(args, &mut index, "--device")?.to_owned()),
            "--target" => target = Some(next_value(args, &mut index, "--target")?.to_owned()),
            "--content" => content = Some(next_value(args, &mut index, "--content")?.to_owned()),
            other => return Err(format!("unsupported prepare option: {other}").into()),
        }
        index += 1;
    }

    let grant_file = grant_file.ok_or("prepare requires --grant-file")?;
    let prepared_out = prepared_out.ok_or("prepare requires --prepared-out")?;
    let device = device.ok_or("prepare requires --device")?;
    let target = target.ok_or("prepare requires --target")?;
    let content = content.ok_or("prepare requires --content")?;
    if prepared_out.exists() {
        return Err("prepared output already exists; refusing to overwrite".into());
    }

    let token = token_from_file(&grant_file)?;
    let listed = rpc(&token, "tools/list", None, None, 10)?;
    let tools = listed
        .get("tools")
        .and_then(Value::as_array)
        .ok_or("tools/list did not return tools")?;
    let names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();

    for required in ["prepare_write", "commit_write"] {
        if !names.contains(required) {
            return Err(format!("missing required MCP tool: {required}").into());
        }
    }
    for forbidden in ["write_file", "terminal_exec", "process_terminate"] {
        if names.contains(forbidden) {
            return Err(format!("unsafe MCP tool exposed: {forbidden}").into());
        }
    }

    let prepared = tool_text(rpc(
        &token,
        "tools/call",
        Some("prepare_write"),
        Some(json!({
            "device_id": device,
            "path": target,
            "content_base64": STANDARD.encode(content.as_bytes()),
            "expected_target_sha256": "absent"
        })),
        11,
    )?)?;
    if prepared.get("status").and_then(Value::as_str) != Some("approval_required") {
        return Err(format!(
            "prepare_write returned unexpected status: {:?}",
            prepared.get("status")
        )
        .into());
    }

    let artifact = json!({
        "device_id": device,
        "target": target,
        "content": content,
        "request_base64": prepared.get("request_base64").ok_or("missing request_base64")?,
        "challenge": prepared.get("challenge").ok_or("missing challenge")?,
        "content_sha256": prepared.get("content_sha256")
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
            "target": artifact["target"],
            "prepare_write_exposed": true,
            "commit_write_exposed": true,
            "unsafe_tools_exposed": []
        })
    );
    Ok(())
}

fn commit_command(args: &[String]) -> Result<(), AnyError> {
    let mut grant_file = None::<PathBuf>;
    let mut prepared_file = None::<PathBuf>;
    let mut approval_file = None::<PathBuf>;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--grant-file" => grant_file = Some(next_path(args, &mut index, "--grant-file")?),
            "--prepared-file" => {
                prepared_file = Some(next_path(args, &mut index, "--prepared-file")?)
            }
            "--approval-file" => {
                approval_file = Some(next_path(args, &mut index, "--approval-file")?)
            }
            other => return Err(format!("unsupported commit option: {other}").into()),
        }
        index += 1;
    }

    let grant_file = grant_file.ok_or("commit requires --grant-file")?;
    let prepared_file = prepared_file.ok_or("commit requires --prepared-file")?;
    let approval_file = approval_file.ok_or("commit requires --approval-file")?;
    let token = token_from_file(&grant_file)?;

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
        "approval_base64": approval
    });

    let committed = tool_text(rpc(
        &token,
        "tools/call",
        Some("commit_write"),
        Some(arguments.clone()),
        12,
    )?)?;
    if committed.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(format!(
            "commit_write returned unexpected status: {:?}",
            committed.get("status")
        )
        .into());
    }

    let replayed = tool_text(rpc(
        &token,
        "tools/call",
        Some("commit_write"),
        Some(arguments),
        13,
    )?)?;
    if replayed.get("status").and_then(Value::as_str) != Some("approval_replayed") {
        return Err(format!(
            "replay returned unexpected status: {:?}",
            replayed.get("status")
        )
        .into());
    }

    let readback = tool_text(rpc(
        &token,
        "tools/call",
        Some("read_file"),
        Some(json!({
            "device_id": device_id,
            "path": prepared["target"].as_str().ok_or("prepared target missing")?
        })),
        14,
    )?)?;
    if readback.get("status").and_then(Value::as_str) != Some("ok")
        || readback.get("encoding").and_then(Value::as_str) != Some("base64")
    {
        return Err("readback did not return successful base64 content".into());
    }
    let actual = STANDARD.decode(
        readback["data"]
            .as_str()
            .ok_or("readback base64 payload missing")?
            .as_bytes(),
    )?;
    if actual
        != prepared["content"]
            .as_str()
            .ok_or("prepared content missing")?
            .as_bytes()
    {
        return Err("readback content mismatch".into());
    }

    println!(
        "{}",
        json!({
            "live_m1": "PASS",
            "prepare": "approval_required",
            "commit": "ok",
            "replay": "approval_replayed",
            "readback": "ok",
            "target": prepared["target"],
            "content_sha256": prepared["content_sha256"]
        })
    );
    Ok(())
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
                "name": "vor-m1-live-canary",
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

fn token_from_file(path: &Path) -> Result<String, AnyError> {
    let text = fs::read_to_string(path)?;
    for line in text.lines() {
        if let Some(token) = line.strip_prefix("token=") {
            let token = token.trim();
            if !token.is_empty() {
                return Ok(token.to_owned());
            }
        }
    }
    Err("grant file contains no token".into())
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
    println!("Vör M1 live canary helper");
    println!(
        "  vor-m1-canary prepare --grant-file FILE --prepared-out FILE --device ID --target PATH --content TEXT"
    );
    println!("  vor-m1-canary commit --grant-file FILE --prepared-file FILE --approval-file FILE");
    println!("The grant token is read locally and is never printed.");
}
