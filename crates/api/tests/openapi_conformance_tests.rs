//! OpenAPI response-shape conformance tests.
//!
//! These tests load `docs/openapi.yaml`, build a JSON Schema validator for each
//! documented response, exercise the corresponding endpoint through the test
//! app harness, and assert that:
//!
//!   1. The HTTP status code is documented for that operation.
//!   2. The JSON response body validates against the documented schema.
//!   3. No undocumented fields are present (drift fails the test).
//!
//! The goal is to catch drift between `docs/openapi.yaml` and the real
//! handlers. If a handler starts returning a new field, or a documented field
//! disappears, or a status code changes, these tests should fail.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::TestApp;
use jsonschema::JSONSchema;
use serde_json::Value;
use tower::ServiceExt;

/// Location of the OpenAPI document, relative to the crate root
/// (`crates/api`). `CARGO_MANIFEST_DIR` points at `crates/api`, so we walk up
/// two levels to reach the workspace root.
fn openapi_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("..")
        .join("..")
        .join("docs")
        .join("openapi.yaml")
}

/// Load and parse the OpenAPI document as a `serde_json::Value`.
fn load_openapi() -> Value {
    let path = openapi_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let yaml: serde_yaml::Value = serde_yaml::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {} as YAML: {e}", path.display()));
    // Round-trip through serde_json so we get a uniform JSON value to work
    // with (jsonschema expects JSON).
    serde_json::to_value(yaml).expect("failed to convert OpenAPI YAML to JSON value")
}

/// Resolve a local `$ref` (e.g. `#/components/schemas/Foo`) against the root
/// document. Only supports the `#/...` form used by OpenAPI documents.
fn resolve_ref<'a>(root: &'a Value, reference: &str) -> &'a Value {
    let pointer = reference
        .strip_prefix('#')
        .unwrap_or_else(|| panic!("unsupported $ref (must start with '#'): {reference}"));
    root.pointer(pointer)
        .unwrap_or_else(|| panic!("could not resolve $ref {reference}"))
}

/// Recursively inline `$ref`s so the resulting schema can be handed to
/// `jsonschema` without needing a resolver. We also inject
/// `additionalProperties: false` on every object schema that does not already
/// specify it, so that undocumented fields cause validation to fail.
fn inline_and_seal(root: &Value, node: &Value) -> Value {
    match node {
        Value::Object(map) => {
            // If this node is a `$ref`, resolve and recurse.
            if let Some(Value::String(reference)) = map.get("$ref") {
                let resolved = resolve_ref(root, reference);
                return inline_and_seal(root, resolved);
            }

            let mut out = serde_json::Map::new();
            for (key, value) in map {
                let inlined = match key.as_str() {
                    // `properties` maps field names to schemas; recurse into
                    // each value but keep the keys as-is.
                    "properties" => {
                        if let Value::Object(props) = value {
                            let mut new_props = serde_json::Map::new();
                            for (prop_name, prop_schema) in props {
                                new_props.insert(
                                    prop_name.clone(),
                                    inline_and_seal(root, prop_schema),
                                );
                            }
                            Value::Object(new_props)
                        } else {
                            value.clone()
                        }
                    }
                    // `items`, `additionalProperties`, `allOf`, `anyOf`,
                    // `oneOf`, `not` all contain schemas; recurse.
                    "items" | "additionalProperties" | "not" => {
                        inline_and_seal(root, value)
                    }
                    "allOf" | "anyOf" | "oneOf" => {
                        if let Value::Array(arr) = value {
                            Value::Array(
                                arr.iter().map(|v| inline_and_seal(root, v)).collect(),
                            )
                        } else {
                            value.clone()
                        }
                    }
                    _ => value.clone(),
                };
                out.insert(key.clone(), inlined);
            }

            // Seal object schemas: if this schema describes an object (has
            // `properties` or `type: object`) and does not already declare
            // `additionalProperties`, set it to `false` so undocumented fields
            // fail validation.
            let is_object = out
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| t == "object")
                .unwrap_or(false)
                || out.contains_key("properties");
            if is_object && !out.contains_key("additionalProperties") {
                out.insert("additionalProperties".into(), Value::Bool(false));
            }

            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| inline_and_seal(root, v)).collect()),
        other => other.clone(),
    }
}

/// Build a compiled JSON Schema validator for a given response schema node.
fn build_validator(root: &Value, schema: &Value) -> JSONSchema {
    let inlined = inline_and_seal(root, schema);
    JSONSchema::compile(&inlined)
        .unwrap_or_else(|e| panic!("failed to compile schema: {e}\nSchema: {inlined:#}"))
}

/// A single documented operation to exercise.
struct Operation {
    method: Method,
    /// Path template as written in the OpenAPI document (e.g. `/items/{id}`).
    path_template: String,
    /// Concrete path to request (with template params substituted).
    concrete_path: String,
    /// The operation object from the OpenAPI document.
    operation: Value,
}

/// Collect all documented operations from the OpenAPI document.
fn collect_operations(root: &Value) -> Vec<Operation> {
    let paths = root
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("OpenAPI document has no `paths` object");

    let mut ops = Vec::new();
    for (path_template, path_item) in paths {
        let path_item = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };
        for (method_str, operation) in path_item {
            let method = match method_str.to_ascii_uppercase().as_str() {
                "GET" => Method::GET,
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "PATCH" => Method::PATCH,
                "DELETE" => Method::DELETE,
                "HEAD" => Method::HEAD,
                "OPTIONS" => Method::OPTIONS,
                _ => continue, // skip `parameters`, `summary`, etc.
            };
            let concrete_path = substitute_path_params(path_template);
            ops.push(Operation {
                method,
                path_template: path_template.clone(),
                concrete_path,
                operation: operation.clone(),
            });
        }
    }
    ops
}

/// Replace `{param}` segments with a placeholder value. Handlers under test
/// are expected to return a documented 4xx (e.g. 404) for unknown ids, which
/// is itself a documented shape we validate.
fn substitute_path_params(path_template: &str) -> String {
    let mut out = String::with_capacity(path_template.len());
    let mut chars = path_template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            // consume until '}'
            for inner in chars.by_ref() {
                if inner == '}' {
                    break;
                }
            }
            out.push_str("00000000-0000-0000-0000-000000000000");
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract the set of documented status codes for an operation.
fn documented_status_codes(operation: &Value) -> BTreeSet<u16> {
    operation
        .get("responses")
        .and_then(|r| r.as_object())
        .map(|responses| {
            responses
                .keys()
                .filter_map(|k| k.parse::<u16>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the JSON schema for a given status code from an operation, if any.
fn response_schema<'a>(root: &'a Value, operation: &'a Value, status: u16) -> Option<&'a Value> {
    let responses = operation.get("responses")?.as_object()?;
    let response = responses.get(&status.to_string())?;
    let content = response.get("content")?.as_object()?;
    let json = content.get("application/json")?;
    json.get("schema")
}

/// Send a request through the test app and return (status, parsed JSON body).
async fn call(app: &TestApp, method: Method, path: &str) -> (StatusCode, Option<Value>) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("accept", "application/json")
        .body(Body::empty())
        .expect("failed to build request");

    let response = app
        .router()
        .clone()
        .oneshot(request)
        .await
        .expect("router call failed");

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("failed to read response body");

    let json = if body_bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&body_bytes).ok()
    };

    (status, json)
}

/// Validate a JSON body against a schema, collecting all errors.
fn validate_body(schema: &JSONSchema, body: &Value, context: &str) {
    if let Err(errors) = schema.validate(body) {
        let messages: Vec<String> = errors.map(|e| format!("  - {e}")).collect();
        panic!(
            "{context}: response body does not match documented schema:\n{}\nBody: {}",
            messages.join("\n"),
            serde_json::to_string_pretty(body).unwrap_or_default()
        );
    }
}

/// Core conformance check for a single operation.
async fn check_operation(app: &TestApp, root: &Value, op: &Operation) {
    let documented = documented_status_codes(&op.operation);
    assert!(
        !documented.is_empty(),
        "operation {} {} documents no responses",
        op.method,
        op.path_template
    );

    let (status, body) = call(app, op.method.clone(), &op.concrete_path).await;
    let status_u16 = status.as_u16();

    assert!(
        documented.contains(&status_u16),
        "operation {} {} returned undocumented status {} (documented: {:?})",
        op.method,
        op.path_template,
        status_u16,
        documented
    );

    // If the documented response has a JSON schema, validate the body.
    if let Some(schema_node) = response_schema(root, &op.operation, status_u16) {
        let validator = build_validator(root, schema_node);
        let body = body.unwrap_or_else(|| {
            panic!(
                "operation {} {} returned status {} with empty/non-JSON body, but a JSON schema is documented",
                op.method, op.path_template, status_u16
            )
        });
        validate_body(
            &validator,
            &body,
            &format!("{} {} -> {}", op.method, op.path_template, status_u16),
        );
    }
}

#[tokio::test]
async fn openapi_document_parses() {
    // Sanity check: the document must load and contain paths.
    let root = load_openapi();
    assert!(
        root.get("paths").and_then(|p| p.as_object()).is_some(),
        "OpenAPI document must contain a `paths` object"
    );
}

#[tokio::test]
async fn all_documented_operations_conform() {
    let root = load_openapi();
    let app = TestApp::new().await;
    let operations = collect_operations(&root);

    assert!(
        !operations.is_empty(),
        "no operations found in OpenAPI document"
    );

    let mut failures = Vec::new();
    for op in &operations {
        // Run each check in isolation so one failure doesn't mask others.
        let result = std::panic::AssertUnwindSafe(check_operation(&app, &root, op));
        if let Err(panic) = futures::FutureExt::catch_unwind(result).await {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".to_string());
            failures.push(format!("{} {}: {}", op.method, op.path_template, msg));
        }
    }

    if !failures.is_empty() {
        panic!(
            "OpenAPI conformance failures ({}):\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
}

/// Explicitly verify that undocumented fields are rejected. This guards the
/// `additionalProperties: false` sealing logic itself: if the sealing were
/// broken, this test would fail even when handlers are correct.
#[test]
fn sealing_rejects_undocumented_fields() {
    let root: Value = serde_json::json!({
        "components": {
            "schemas": {
                "Thing": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" }
                    }
                }
            }
        }
    });

    let schema_node = serde_json::json!({ "$ref": "#/components/schemas/Thing" });
    let validator = build_validator(&root, &schema_node);

    // Documented shape passes.
    let ok = serde_json::json!({ "id": "abc" });
    assert!(validator.is_valid(&ok), "documented shape should validate");

    // Undocumented field fails.
    let drift = serde_json::json!({ "id": "abc", "surprise": true });
    assert!(
        !validator.is_valid(&drift),
        "undocumented field should be rejected"
    );
}

/// Verify that a documented 4xx shape (e.g. an error envelope) is validated
/// when the handler returns it. This exercises the "common 4xx" coverage
/// requirement against a synthetic operation.
#[test]
fn error_envelope_schema_validates() {
    let root: Value = serde_json::json!({
        "components": {
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" }
                    }
                }
            }
        }
    });

    let schema_node = serde_json::json!({ "$ref": "#/components/schemas/Error" });
    let validator = build_validator(&root, &schema_node);

    assert!(validator.is_valid(&serde_json::json!({ "error": "not found" })));
    assert!(!validator.is_valid(&serde_json::json!({ "error": "not found", "code": 404 })));
    assert!(!validator.is_valid(&serde_json::json!({})));
}
