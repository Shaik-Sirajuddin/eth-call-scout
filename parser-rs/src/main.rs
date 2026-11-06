use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Node, Parser};

const ETH_METHODS: &[&str] = &[
    "eth_call",
    "eth_sendTransaction",
    "eth_estimateGas",
    "eth_getBalance",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getLogs",
    "eth_blockNumber",
    "eth_chainId",
    "eth_gasPrice",
    "eth_feeHistory",
    "eth_getTransactionCount",
];
const EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    ".cache",
];

#[derive(Serialize)]
struct ScanOutput {
    scanned_files: usize,
    findings: Vec<Value>,
}

fn source_text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.start_byte()..node.end_byte()]).unwrap_or("")
}
fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}
fn child_field<'a>(node: Node<'a>, field: &str) -> Option<Node<'a>> {
    node.child_by_field_name(field)
}
fn first_named(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().next()
}
fn string_value(node: Node<'_>, source: &[u8]) -> Option<String> {
    let text = source_text(node, source).trim();
    if node.kind() == "string"
        || node.kind() == "string_fragment"
        || node.kind() == "template_string"
        || node.kind() == "template_literal"
    {
        if text.starts_with(['\'', '"']) && text.len() >= 2 {
            return Some(text[1..text.len() - 1].to_string());
        }
        if text.starts_with('`') && text.ends_with('`') && !text.contains("${") {
            return Some(text[1..text.len() - 1].to_string());
        }
    }
    None
}
fn member_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "member_expression" | "optional_member_expression" => {
            child_field(node, "property").map(|n| source_text(n, source).trim().to_string())
        }
        "subscript_expression" => child_field(node, "index")
            .and_then(|n| string_value(n, source))
            .or_else(|| child_field(node, "index").map(|n| source_text(n, source).to_string())),
        "identifier" | "property_identifier" => Some(source_text(node, source).to_string()),
        _ => None,
    }
}
fn root_identifier(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(source_text(node, source).to_string()),
        "member_expression" | "optional_member_expression" | "subscript_expression" => {
            child_field(node, "object").and_then(|n| root_identifier(n, source))
        }
        "call_expression" => child_field(node, "function").and_then(|n| root_identifier(n, source)),
        _ => first_named(node).and_then(|n| root_identifier(n, source)),
    }
}
fn property_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    child_field(node, "key")
        .map(|n| {
            string_value(n, source).unwrap_or_else(|| source_text(n, source).trim().to_string())
        })
        .or_else(|| {
            first_named(node).map(|n| {
                string_value(n, source).unwrap_or_else(|| source_text(n, source).trim().to_string())
            })
        })
}
fn resolve(
    node: Option<Node<'_>>,
    source: &[u8],
    vars: &HashMap<String, Value>,
    depth: usize,
) -> Value {
    let Some(node) = node else {
        return Value::Null;
    };
    if depth > 6 {
        return json!(source_text(node, source));
    }
    let text = source_text(node, source).trim();
    if let Some(value) = string_value(node, source) {
        return json!(value);
    }
    match node.kind() {
        "number" => {
            if let Ok(v) = text.parse::<i64>() {
                return json!(v);
            }
            if let Ok(v) = text.parse::<f64>() {
                return json!(v);
            }
            return json!(text);
        }
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        "null" => return Value::Null,
        "identifier" | "type_identifier" => {
            return vars.get(text).cloned().unwrap_or_else(|| json!(text));
        }
        "array" => {
            return json!(
                named_children(node)
                    .into_iter()
                    .map(|n| resolve(Some(n), source, vars, depth + 1))
                    .collect::<Vec<_>>()
            );
        }
        "object" => {
            let mut result = Map::new();
            for item in named_children(node) {
                if item.kind() == "pair" || item.kind() == "method_definition" {
                    if let Some(key) = property_name(item, source) {
                        let value = child_field(item, "value")
                            .or_else(|| named_children(item).get(1).copied());
                        result.insert(key, resolve(value, source, vars, depth + 1));
                    }
                } else if item.kind().contains("property_identifier")
                    || item.kind() == "shorthand_property_identifier"
                {
                    let key = source_text(item, source).to_string();
                    result.insert(
                        key.clone(),
                        vars.get(&key).cloned().unwrap_or_else(|| json!(key)),
                    );
                }
            }
            return Value::Object(result);
        }
        _ => return json!(text),
    }
}
fn object_property<'a>(node: Option<Node<'a>>, name: &str, source: &[u8]) -> Option<Node<'a>> {
    let node = node?;
    if node.kind() != "object" {
        return None;
    }
    for pair in named_children(node) {
        if pair.kind() == "pair" && property_name(pair, source).as_deref() == Some(name) {
            return child_field(pair, "value").or_else(|| named_children(pair).get(1).copied());
        }
    }
    None
}
fn args(node: Node<'_>) -> Vec<Node<'_>> {
    child_field(node, "arguments")
        .map(named_children)
        .unwrap_or_default()
}
fn tx_details(value: &Value) -> Value {
    let obj = value.as_object();
    let from = obj
        .and_then(|o| o.get("from").or_else(|| o.get("account")).cloned())
        .unwrap_or(Value::Null);
    json!({"from": from, "to": obj.and_then(|o| o.get("to")).cloned().unwrap_or(Value::Null),
        "value": obj.and_then(|o| o.get("value")).cloned().unwrap_or(Value::Null),
        "gas": obj.and_then(|o| o.get("gas").or_else(|| o.get("gasLimit"))).cloned().unwrap_or(Value::Null),
        "gasPrice": obj.and_then(|o| o.get("gasPrice")).cloned().unwrap_or(Value::Null),
        "maxFeePerGas": obj.and_then(|o| o.get("maxFeePerGas")).cloned().unwrap_or(Value::Null),
        "nonce": obj.and_then(|o| o.get("nonce")).cloned().unwrap_or(Value::Null)})
}
fn function_context(node: Node<'_>, source: &[u8]) -> String {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if matches!(
            parent.kind(),
            "function_declaration"
                | "function_expression"
                | "method_definition"
                | "generator_function_declaration"
        ) {
            if let Some(name) = child_field(parent, "name") {
                return source_text(name, source).to_string();
            }
            if parent.kind() == "method_definition" {
                if let Some(name) = first_named(parent) {
                    return source_text(name, source).to_string();
                }
            }
        }
        if matches!(parent.kind(), "arrow_function" | "function_expression") {
            let mut p = parent;
            while let Some(up) = p.parent() {
                if up.kind() == "variable_declarator" {
                    if let Some(name) = child_field(up, "name") {
                        return source_text(name, source).to_string();
                    }
                }
                if matches!(up.kind(), "statement_block" | "program") {
                    break;
                }
                p = up;
            }
        }
        cur = parent;
    }
    "(top level)".to_string()
}
fn is_address(value: &Value) -> bool {
    value
        .as_str()
        .map(|s| {
            s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
        })
        .unwrap_or(false)
}
fn add_finding(
    findings: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    node: Node<'_>,
    source: &[u8],
    file: &str,
    data: Value,
) {
    let row = node.start_position().row + 1;
    let col = node.start_position().column + 1;
    let key = format!(
        "{row}:{col}:{}:{}",
        data.get("kind").and_then(Value::as_str).unwrap_or(""),
        data.get("rpcMethod").and_then(Value::as_str).unwrap_or("")
    );
    if !seen.insert(key) {
        return;
    }
    let text = source_text(node, source);
    let snippet: String = text.chars().take(600).collect();
    let mut result = json!({"id": format!("{}:{}:{}", Path::new(file).file_name().and_then(|x| x.to_str()).unwrap_or(file), row, col),
        "file": file, "line": row, "column": col, "endLine": node.end_position().row + 1,
        "function": function_context(node, source), "snippet": snippet, "address": null, "functionName": null,
        "parameters": null, "rpcMethod": null, "transaction": null, "library":"unknown", "kind":"contract", "confidence":"medium", "notes":[]});
    if let (Some(dst), Some(src)) = (result.as_object_mut(), data.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    findings.push(result);
}
fn walk(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    vars: &mut HashMap<String, Value>,
    contracts: &mut HashMap<String, String>,
    findings: &mut Vec<Value>,
    seen: &mut HashSet<String>,
) {
    if node.kind() == "variable_declarator" {
        if let (Some(name), Some(value_node)) =
            (child_field(node, "name"), child_field(node, "value"))
        {
            let key = source_text(name, source).to_string();
            if value_node.kind() == "new_expression" {
                let ctor =
                    child_field(value_node, "constructor").or_else(|| first_named(value_node));
                let ctor_name = ctor.and_then(|x| root_identifier(x, source));
                let new_args = args(value_node);
                let address = resolve(new_args.first().copied(), source, vars, 0);
                if matches!(ctor_name.as_deref(), Some("Contract" | "Interface"))
                    && is_address(&address)
                {
                    contracts.insert(key.clone(), address.as_str().unwrap().to_string());
                }
            }
            let resolved = resolve(Some(value_node), source, vars, 0);
            vars.insert(key, resolved);
        }
    }
    if node.kind() == "call_expression" {
        let function = child_field(node, "function").or_else(|| first_named(node));
        let method = function.and_then(|f| member_name(f, source));
        let arg_nodes = args(node);
        let receiver = function.and_then(|f| child_field(f, "object"));
        let receiver_name = receiver.and_then(|r| root_identifier(r, source));
        let contract_address = receiver_name
            .as_ref()
            .and_then(|n| contracts.get(n))
            .cloned();

        if let (Some(address), Some(method_name)) = (contract_address, method.as_deref()) {
            if ![
                "connect",
                "attach",
                "interface",
                "getAddress",
                "waitForDeployment",
            ]
            .contains(&method_name)
            {
                let function_name = if ["staticCall", "send", "estimateGas"].contains(&method_name)
                {
                    function
                        .and_then(|f| child_field(f, "object"))
                        .and_then(|x| member_name(x, source))
                } else {
                    Some(method_name.to_string())
                };
                if let Some(fn_name) = function_name {
                    let params: Vec<Value> = arg_nodes
                        .iter()
                        .map(|a| resolve(Some(*a), source, vars, 0))
                        .collect();
                    add_finding(
                        findings,
                        seen,
                        node,
                        source,
                        file,
                        json!({"address":address,"transaction":{"to":address},"functionName":fn_name,"parameters":params,"library":"ethers","kind":if ["staticCall", "callStatic"].contains(&method_name) {"contract read"} else {"contract interaction"},"confidence":"high","notes":[]}),
                    );
                }
            }
        }
        if let Some(name) = method.as_deref() {
            if [
                "readContract",
                "writeContract",
                "simulateContract",
                "getContract",
            ]
            .contains(&name)
            {
                let cfg = arg_nodes.first().copied();
                let addr = resolve(object_property(cfg, "address", source), source, vars, 0);
                let fn_name = resolve(
                    object_property(cfg, "functionName", source),
                    source,
                    vars,
                    0,
                );
                let params = resolve(object_property(cfg, "args", source), source, vars, 0);
                let mut notes = Vec::new();
                if !is_address(&addr) {
                    notes.push("Address is dynamic or unresolved.");
                }
                add_finding(
                    findings,
                    seen,
                    node,
                    source,
                    file,
                    json!({"address":if is_address(&addr){addr.clone()}else{Value::Null},"transaction":{"to":if is_address(&addr){addr.clone()}else{Value::Null}},"functionName":if fn_name.is_string(){fn_name}else{Value::Null},"parameters":if params.is_null(){json!([])}else{params},"library":"viem","kind":if name == "readContract" {"contract read"} else {"contract interaction"},"confidence":if is_address(&addr){"high"}else{"medium"},"notes":notes}),
                );
            }
            if name == "request" {
                let cfg = arg_nodes.first().copied();
                let rpc = resolve(object_property(cfg, "method", source), source, vars, 0);
                let params = resolve(object_property(cfg, "params", source), source, vars, 0);
                if let Some(rpc_name) = rpc.as_str().filter(|m| ETH_METHODS.contains(m)) {
                    let first = params
                        .as_array()
                        .and_then(|x| x.first())
                        .cloned()
                        .unwrap_or(Value::Null);
                    let addr = first.get("to").cloned().unwrap_or(Value::Null);
                    let data = first.get("data").cloned().unwrap_or(Value::Null);
                    let mut notes = Vec::new();
                    if data.is_string() {
                        notes.push("Raw calldata captured; function name and decoded arguments require the matching ABI.");
                    } else if rpc_name == "eth_call" {
                        notes.push("Contract target or calldata is dynamic or unresolved.");
                    }
                    add_finding(
                        findings,
                        seen,
                        node,
                        source,
                        file,
                        json!({"rpcMethod":rpc_name,"address":if is_address(&addr){addr.clone()}else{Value::Null},"transaction":tx_details(&first),"calldata":if data.is_string(){data.clone()}else{Value::Null},"parameters":if data.is_null(){params}else{data},"library":"native JSON-RPC","kind":if rpc_name == "eth_call" {"contract read"}else{"Ethereum JSON-RPC"},"confidence":"high","notes":notes}),
                    );
                }
            }
            if ["send", "sendAsync"].contains(&name) && !arg_nodes.is_empty() {
                let rpc = resolve(arg_nodes.first().copied(), source, vars, 0);
                let params = resolve(arg_nodes.get(1).copied(), source, vars, 0);
                if let Some(rpc_name) = rpc.as_str().filter(|m| ETH_METHODS.contains(m)) {
                    let first = params
                        .as_array()
                        .and_then(|x| x.first())
                        .cloned()
                        .unwrap_or(Value::Null);
                    let addr = first.get("to").cloned().unwrap_or(Value::Null);
                    let data = first.get("data").cloned().unwrap_or(Value::Null);
                    let notes = if data.is_string() {
                        vec![
                            "Raw calldata captured; function name and decoded arguments require the matching ABI.",
                        ]
                    } else {
                        vec![]
                    };
                    add_finding(
                        findings,
                        seen,
                        node,
                        source,
                        file,
                        json!({"rpcMethod":rpc_name,"address":if is_address(&addr){addr.clone()}else{Value::Null},"transaction":tx_details(&first),"calldata":if data.is_string(){data.clone()}else{Value::Null},"parameters":if data.is_null(){params}else{data},"library":"native JSON-RPC","kind":if rpc_name == "eth_call" {"contract read"}else{"Ethereum JSON-RPC"},"confidence":"high","notes":notes}),
                    );
                }
            }
            if name == "fetch" && arg_nodes.len() > 1 {
                let body = object_property(arg_nodes.get(1).copied(), "body", source);
                if let Some(body) = body {
                    let body_args = args(body);
                    if body.kind() == "call_expression"
                        && body_args.len() > 0
                        && member_name(child_field(body, "function").unwrap_or(body), source)
                            .as_deref()
                            == Some("stringify")
                    {
                        let payload = body_args[0];
                        let rpc = resolve(
                            object_property(Some(payload), "method", source),
                            source,
                            vars,
                            0,
                        );
                        let params = resolve(
                            object_property(Some(payload), "params", source),
                            source,
                            vars,
                            0,
                        );
                        if let Some(rpc_name) = rpc.as_str().filter(|m| ETH_METHODS.contains(m)) {
                            let first = params
                                .as_array()
                                .and_then(|x| x.first())
                                .cloned()
                                .unwrap_or(Value::Null);
                            let addr = first.get("to").cloned().unwrap_or(Value::Null);
                            let data = first.get("data").cloned().unwrap_or(Value::Null);
                            let mut notes = vec!["Direct HTTP JSON-RPC request detected."];
                            if data.is_string() {
                                notes.push("Raw calldata requires an ABI to decode.");
                            }
                            add_finding(
                                findings,
                                seen,
                                node,
                                source,
                                file,
                                json!({"rpcMethod":rpc_name,"address":if is_address(&addr){addr.clone()}else{Value::Null},"transaction":tx_details(&first),"calldata":if data.is_string(){data.clone()}else{Value::Null},"parameters":if data.is_null(){params}else{data},"library":"native JSON-RPC (fetch)","kind":if rpc_name == "eth_call" {"contract read"}else{"Ethereum JSON-RPC"},"confidence":"high","notes":notes}),
                            );
                        }
                    }
                }
            }
            if name == "call"
                && !arg_nodes.is_empty()
                && object_property(arg_nodes.first().copied(), "to", source).is_some()
            {
                let cfg = arg_nodes[0];
                let cfg_value = resolve(Some(cfg), source, vars, 0);
                let addr = resolve(object_property(Some(cfg), "to", source), source, vars, 0);
                let data = resolve(object_property(Some(cfg), "data", source), source, vars, 0);
                add_finding(
                    findings,
                    seen,
                    node,
                    source,
                    file,
                    json!({"address":if is_address(&addr){addr.clone()}else{Value::Null},"transaction":{"to":addr},"calldata":if data.is_string(){data.clone()}else{Value::Null},"parameters":data,"rpcMethod":"eth_call","library":if ["provider", "ethersProvider"].contains(&receiver_name.as_deref().unwrap_or("")){"ethers"}else{"native JSON-RPC"},"kind":"contract read","confidence":"high","notes":["Raw calldata captured; function name and decoded arguments require the matching ABI."]}),
                );
                let _ = cfg_value;
            }
        }
    }
    for child in named_children(node) {
        walk(child, source, file, vars, contracts, findings, seen);
    }
}
fn language_for(path: &Path) -> Option<Language> {
    match path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "js" | "jsx" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" | "mts" | "cts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}
fn import_specifiers(root: Node<'_>, source: &[u8], out: &mut Vec<String>) {
    if matches!(root.kind(), "import_statement" | "export_statement") {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if let Some(value) = string_value(node, source) {
                out.push(value);
            } else {
                stack.extend(named_children(node));
            }
        }
    }
    if root.kind() == "call_expression" {
        let f = child_field(root, "function");
        let is_import = f
            .map(|n| source_text(n, source) == "import" || source_text(n, source) == "require")
            .unwrap_or(false);
        if is_import {
            if let Some(arg) = args(root).first() {
                if let Some(s) = string_value(*arg, source) {
                    out.push(s);
                }
            }
        }
    }
    for child in named_children(root) {
        import_specifiers(child, source, out);
    }
}
fn candidate_files(base: &Path) -> Vec<PathBuf> {
    let mut out = vec![base.to_path_buf()];
    for ext in EXTENSIONS {
        out.push(base.with_extension(ext));
    }
    for ext in EXTENSIONS {
        out.push(base.join(format!("index.{ext}")));
    }
    out
}
fn package_root(specifier: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = specifier.split('/').collect();
    if specifier.starts_with('@') && parts.len() >= 2 {
        (
            format!("{}/{}", parts[0], parts[1]),
            if parts.len() > 2 {
                Some(parts[2..].join("/"))
            } else {
                None
            },
        )
    } else {
        (
            parts[0].to_string(),
            if parts.len() > 1 {
                Some(parts[1..].join("/"))
            } else {
                None
            },
        )
    }
}
fn resolve_import(specifier: &str, from: &Path) -> Option<PathBuf> {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        let base = if specifier.starts_with('/') {
            PathBuf::from(specifier)
        } else {
            from.parent()?.join(specifier)
        };
        return candidate_files(&base)
            .into_iter()
            .find(|p| p.is_file() && is_source(p));
    }
    if specifier.starts_with("node:") || specifier.contains("://") {
        return None;
    }
    let (pkg, sub) = package_root(specifier);
    let mut dir = from.parent()?.to_path_buf();
    loop {
        let package = dir.join("node_modules").join(&pkg);
        if package.is_dir() {
            let base = if let Some(subpath) = sub.as_deref() {
                package.join(subpath)
            } else {
                let meta_path = package.join("package.json");
                let metadata: Value = fs::read_to_string(meta_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                let target = metadata
                    .get("module")
                    .or_else(|| metadata.get("main"))
                    .or_else(|| metadata.get("source"))
                    .and_then(Value::as_str)
                    .unwrap_or("index.js");
                package.join(target)
            };
            if let Some(found) = candidate_files(&base)
                .into_iter()
                .find(|p| p.is_file() && is_source(p))
            {
                return Some(found);
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}
fn is_source(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|e| EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
        && !path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .ends_with(".d.ts")
}
fn collect_files(inputs: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    for raw in inputs {
        let path = PathBuf::from(raw);
        if !path.exists() {
            return Err(format!("Path does not exist: {raw}"));
        }
        if path.is_dir() {
            let mut stack = vec![path];
            while let Some(dir) = stack.pop() {
                let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        if !SKIP_DIRS
                            .contains(&p.file_name().and_then(|x| x.to_str()).unwrap_or(""))
                        {
                            stack.push(p)
                        }
                    } else if is_source(&p) {
                        roots.push(p)
                    }
                }
            }
        } else if is_source(&path) {
            roots.push(path)
        }
    }
    let mut visited = HashSet::new();
    let mut queue = roots;
    let mut ordered = Vec::new();
    while let Some(file) = queue.pop() {
        let file = fs::canonicalize(&file).unwrap_or(file);
        if !visited.insert(file.clone()) {
            continue;
        }
        let src = match fs::read(&file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut parser = Parser::new();
        if let Some(lang) = language_for(&file) {
            if parser.set_language(&lang).is_ok() {
                if let Some(tree) = parser.parse(&src, None) {
                    let mut imports = Vec::new();
                    import_specifiers(tree.root_node(), &src, &mut imports);
                    for spec in imports {
                        if let Some(dep) = resolve_import(&spec, &file) {
                            if !visited.contains(&dep) {
                                queue.push(dep)
                            }
                        }
                    }
                }
            }
        }
        ordered.push(file);
    }
    ordered.sort();
    Ok(ordered)
}
fn scan(files: &[PathBuf]) -> Vec<Value> {
    let mut findings = Vec::new();
    for path in files {
        let display = path.to_string_lossy().to_string();
        let source = match fs::read(path) {
            Ok(s) => s,
            Err(e) => {
                findings.push(json!({"id":format!("{display}:error"),"file":display,"line":0,"column":0,"function":"","snippet":"","library":"parser","kind":"parse error","confidence":"low","notes":[e.to_string()]}));
                continue;
            }
        };
        let Some(language) = language_for(path) else {
            continue;
        };
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(&source, None) else {
            continue;
        };
        let mut vars = HashMap::new();
        let mut contracts = HashMap::new();
        let mut seen = HashSet::new();
        walk(
            tree.root_node(),
            &source,
            &display,
            &mut vars,
            &mut contracts,
            &mut findings,
            &mut seen,
        );
        if tree.root_node().has_error() {
            let mut cursor = tree.root_node().walk();
            for error in tree
                .root_node()
                .children(&mut cursor)
                .filter(|n| n.is_error() || n.is_missing())
            {
                findings.push(json!({"id":format!("{}:{}:parse",display,error.start_position().row+1),"file":display,"line":error.start_position().row+1,"column":error.start_position().column+1,"function":"","snippet":source_text(error,&source),"library":"parser","kind":"parse error","confidence":"low","notes":["Source contains a syntax error near this location; other detections may be incomplete."]}));
            }
        }
    }
    findings.sort_by(|a, b| {
        a["file"]
            .as_str()
            .cmp(&b["file"].as_str())
            .then(a["line"].as_u64().cmp(&b["line"].as_u64()))
            .then(a["column"].as_u64().cmp(&b["column"].as_u64()))
    });
    findings
}
fn run() -> Result<(), String> {
    let inputs: Vec<String> = env::args().skip(1).collect();
    if inputs.is_empty() {
        return Err("Provide one or more source files or directories".into());
    }
    let files = collect_files(&inputs)?;
    let findings = scan(&files);
    let output = ScanOutput {
        scanned_files: files.len(),
        findings,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("eth-call-scout-parser: {e}");
        std::process::exit(1)
    }
}
