//! Integration tests against a mock chat completions server.
//!
//! These check what unit tests cannot: that the request actually carries the signing
//! headers the server verifies, that it reaches the right path, and that the reply
//! arrives labelled untrusted.

use bua_aichat::AichatClient;
use bua_aichat::protocol::{ChatRequest, Message};
use bua_config::Config;
use bua_core::capability::{Capability, CapabilitySet};
use bua_core::event::RecordingSink;
use bua_core::label::Label;
use bua_core::policy::{Policy, ReleasePlan, Routing};
use bua_net::Egress;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

/// What the server received, so tests can assert on the request rather than only the
/// response.
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Serve one canned response, returning the base URL and a channel carrying what was
/// received.
fn serve(response_body: &str) -> (String, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (sender, receiver) = mpsc::channel();
    let response_body = response_body.to_string();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));

        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((name, value));
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).expect("body");

        let _ = sender.send(Captured {
            request_line: request_line.trim().to_string(),
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });

    (format!("http://127.0.0.1:{port}"), receiver)
}

/// Serve an SSE stream, writing each frame separately and flushing between them.
///
/// Written frame by frame rather than as one body, because that is the condition the decoder has
/// to survive: a payload can be split across reads, and one arriving whole in a single read would
/// not exercise the buffering at all.
fn serve_stream(frames: Vec<String>) -> (String, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));

        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((name, value));
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).expect("body");

        let _ = sender.send(Captured {
            request_line: request_line.trim().to_string(),
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });

        // No content-length: the stream ends when the connection closes, as a real one does.
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.flush();

        for frame in frames {
            let _ = stream.write_all(frame.as_bytes());
            let _ = stream.flush();
        }
    });

    (format!("http://127.0.0.1:{port}"), receiver)
}

/// One `data:` frame carrying a chunk.
fn frame(payload: &str) -> String {
    format!("data: {payload}\n\n")
}

fn config_for(endpoint: &str) -> Config {
    Config::from_lookup(|key| match key {
        "SERVICES_KEY_AICHAT" => Some("test-signing-key".into()),
        "BRAVE_SERVICES_KEY_ID" => Some("test-key-id".into()),
        "BRAVE_AI_CHAT_ENDPOINT" => Some(endpoint.to_string()),
        _ => None,
    })
    .expect("config")
}

fn routing() -> Routing {
    let mut r = Routing::new();
    r.insert_trusted("task", "say hello");
    r
}

const REPLY: &str = r#"{"model":"served-model","choices":[{"message":{"role":"assistant","content":"hello from the model"}}]}"#;

#[test]
fn a_completion_round_trips() {
    let (endpoint, received) = serve(REPLY);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let completion = client
        .complete(&mut policy, &request)
        .expect("completion succeeds");

    assert_eq!(completion.model, "served-model");
    // Model output is untrusted, whatever it says.
    assert_eq!(completion.content.label(), Label::untrusted_public());

    let captured = received.recv().expect("request captured");
    assert!(
        captured
            .request_line
            .starts_with("POST /v1/chat/completions"),
        "wrong target: {}",
        captured.request_line
    );
}

/// The server rejects anything without a matching signature, so the headers must be
/// present and in the exact form it verifies.
#[test]
fn the_request_carries_the_signing_headers() {
    let (endpoint, received) = serve(REPLY);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    client.complete(&mut policy, &request).expect("completion");

    let captured = received.recv().expect("request captured");

    let digest = captured.header("digest").expect("digest header");
    assert!(digest.starts_with("SHA-256="), "malformed digest: {digest}");
    // The digest must be over the body actually sent.
    assert_eq!(digest, bua_signing::digest_header(captured.body.as_bytes()));

    let authorization = captured
        .header("authorization")
        .expect("authorization header");
    assert!(authorization.starts_with("Signature keyId=\"test-key-id\""));
    assert!(authorization.contains("algorithm=\"hs2019\""));
    // The server rejects any signed-header set other than exactly "digest".
    assert!(authorization.contains("headers=\"digest\""));

    assert_eq!(
        captured.header("content-type"),
        Some("application/json"),
        "the server expects json"
    );

    // The signing key must never be transmitted.
    for (name, value) in &captured.headers {
        assert!(
            !value.contains("test-signing-key"),
            "the signing key leaked in {name}"
        );
    }
}

#[test]
fn the_request_body_matches_the_protocol() {
    let (endpoint, received) = serve(REPLY);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new(
        "automatic",
        vec![Message::system("be brief"), Message::user("hi")],
    );
    client.complete(&mut policy, &request).expect("completion");

    let captured = received.recv().expect("request captured");
    let body: serde_json::Value = serde_json::from_str(&captured.body).expect("json body");

    assert_eq!(body["model"], "automatic");
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][1]["content"], "hi");
}

/// Without the fetch capability the request must not leave, and the policy records it.
#[test]
fn a_completion_without_the_capability_is_refused() {
    let (endpoint, _received) = serve(REPLY);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::none(),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let error = client
        .complete(&mut policy, &request)
        .expect_err("must be refused");

    assert!(error.to_string().contains("web_fetch"), "got: {error}");
    assert!(!policy.finish());
}

#[test]
fn a_response_without_content_is_an_error() {
    let (endpoint, _received) = serve(r#"{"model":"m","choices":[]}"#);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let error = client
        .complete(&mut policy, &request)
        .expect_err("no content is an error");
    assert!(error.to_string().contains("no message content"));
}

/// A streamed reply must arrive as the same completion a buffered one would have produced, and
/// the count must climb on the way rather than appearing only at the end.
#[test]
fn a_streamed_completion_arrives_in_pieces() {
    let (endpoint, received) = serve_stream(vec![
        frame(r#"{"model":"served-model","choices":[{"delta":{"role":"assistant"}}]}"#),
        frame(r#"{"choices":[{"delta":{"content":"hello"}}]}"#),
        frame(r#"{"choices":[{"delta":{"content":" from"}}]}"#),
        frame(r#"{"choices":[{"delta":{"content":" the model"}}]}"#),
        frame(
            r#"{"choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}"#,
        ),
        frame("[DONE]"),
    ]);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);

    let mut seen = Vec::new();
    let completion = client
        .complete_streaming(&mut policy, &request, |progress| seen.push(progress))
        .expect("streamed completion succeeds");

    assert_eq!(completion.model, "served-model");
    // Streamed or not, model output is untrusted.
    assert_eq!(completion.content.label(), Label::untrusted_public());
    assert_eq!(completion.usage.completion_tokens, 3);

    // The count rose while the reply arrived, which is the point of streaming it.
    let counts: Vec<u64> = seen.iter().map(|p| p.output_tokens).collect();
    assert!(
        counts.windows(2).all(|w| w[1] >= w[0]),
        "the count went backwards: {counts:?}"
    );
    assert!(
        counts.iter().any(|c| *c > 0),
        "the count never moved: {counts:?}"
    );
    // And it ends on the server's figure, not the estimate.
    assert_eq!(seen.last().expect("progress was reported").output_tokens, 3);
    assert!(seen.last().expect("reported").counted_by_server);

    let captured = received.recv().expect("request captured");
    assert!(
        captured.body.contains("\"stream\":true"),
        "the request did not ask to stream: {}",
        captured.body
    );
    assert!(
        captured.body.contains("\"include_usage\":true"),
        "the request did not ask for usage: {}",
        captured.body
    );
}

/// Tool calls arrive fragmented, and a streamed round has to reassemble them into something
/// dispatchable or tool use would break the moment streaming was turned on.
#[test]
fn a_streamed_tool_call_is_reassembled() {
    let (endpoint, _received) = serve_stream(vec![
        frame(
            r#"{"model":"m","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read_file","arguments":""}}]}}]}"#,
        ),
        frame(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\""}}]}}]}"#,
        ),
        frame(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"a.rs\"}"}}]}}]}"#,
        ),
        frame(
            r#"{"choices":[{"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":8,"completion_tokens":5}}"#,
        ),
        frame("[DONE]"),
    ]);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("read a.rs")]);
    let completion = client
        .complete_streaming(&mut policy, &request, |_| {})
        .expect("a tool-calling stream succeeds");

    assert_eq!(completion.calls.len(), 1);
    assert_eq!(completion.calls[0].function.name, "read_file");
    assert_eq!(
        completion.calls[0].arguments().expect("parses")["path"],
        "a.rs"
    );
}

/// The gate runs before any body exists, so a streamed request with no capability is refused
/// exactly as a buffered one is. Streaming must not be a way around the check.
#[test]
fn a_streamed_request_without_the_capability_is_refused() {
    let (endpoint, _received) = serve_stream(vec![frame("[DONE]")]);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::none(),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let error = client
        .complete_streaming(&mut policy, &request, |_| {})
        .expect_err("must be refused");

    assert!(error.to_string().contains("web_fetch"), "got: {error}");
    assert!(!policy.finish());
}

/// A stream that carried nothing usable is an error rather than an empty reply presented as an
/// answer.
#[test]
fn a_stream_with_no_content_is_an_error() {
    let (endpoint, _received) = serve_stream(vec![
        frame(r#"{"model":"m","choices":[{"delta":{"role":"assistant"}}]}"#),
        frame("[DONE]"),
    ]);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let error = client
        .complete_streaming(&mut policy, &request, |_| {})
        .expect_err("no content is an error");
    assert!(error.to_string().contains("no message content"));
}

/// A frame the server sends that is not a chunk must not discard a reply that is otherwise
/// arriving: keepalives and comments are normal.
#[test]
fn unparseable_frames_do_not_lose_the_reply() {
    let (endpoint, _received) = serve_stream(vec![
        ": keepalive\n\n".to_string(),
        frame("not json at all"),
        frame(r#"{"model":"m","choices":[{"delta":{"content":"still here"}}]}"#),
        frame("[DONE]"),
    ]);
    let config = config_for(&endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut client = AichatClient::new(&config, &egress);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    let completion = client
        .complete_streaming(&mut policy, &request, |_| {})
        .expect("a stream with noise in it still succeeds");

    let proof = policy.authorise_display_release("test reads the reply");
    assert_eq!(completion.content.declassify(&proof), "still here");
}

/// A stub subscription handing out one credential, so routing can be tested without a keychain.
struct StubSubscription {
    remaining: usize,
}

impl bua_aichat::Subscription for StubSubscription {
    fn next_credential(&mut self) -> Option<bua_aichat::SubscriptionCredential> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(bua_aichat::SubscriptionCredential {
            cookie_name: "__Secure-sku#brave-leo-premium".to_string(),
            cookie_value: "presented-credential".to_string(),
        })
    }
}

fn premium_config(endpoint: &str, premium: &str) -> Config {
    Config::from_lookup(|key| match key {
        "SERVICES_KEY_AICHAT" => Some("test-signing-key".into()),
        "BRAVE_SERVICES_KEY_ID" => Some("test-key-id".into()),
        "BRAVE_AI_CHAT_ENDPOINT" => Some(endpoint.to_string()),
        "BRAVE_AI_CHAT_PREMIUM_ENDPOINT" => Some(premium.to_string()),
        _ => None,
    })
    .expect("config")
}

/// With a subscription, the request must go to the premium host and carry the credential as the
/// cookie the backend reads. This is what the whole import exists to produce.
#[test]
fn a_subscribed_request_goes_to_the_premium_host_with_the_credential() {
    let (premium_endpoint, received) = serve(REPLY);
    // The free host is a port nothing is listening on, so reaching it would fail rather than
    // quietly pass.
    let config = premium_config("http://127.0.0.1:1", &premium_endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut subscription = StubSubscription { remaining: 1 };
    let mut client = AichatClient::new(&config, &egress).with_subscription(&mut subscription);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    client
        .complete(&mut policy, &request)
        .expect("completion succeeds");

    let captured = received.recv().expect("request captured");
    assert_eq!(
        captured.header("cookie"),
        Some("__Secure-sku#brave-leo-premium=presented-credential")
    );
}

/// Once the batch is spent the request must fall back to the free host, and must not carry a
/// cookie: sending a subscription credential to the free endpoint would leak it to a host it does
/// not belong to.
#[test]
fn an_exhausted_subscription_falls_back_to_the_free_host_without_a_credential() {
    let (free_endpoint, received) = serve(REPLY);
    let config = premium_config(&free_endpoint, "http://127.0.0.1:1");
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut subscription = StubSubscription { remaining: 0 };
    let mut client = AichatClient::new(&config, &egress).with_subscription(&mut subscription);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    client
        .complete(&mut policy, &request)
        .expect("completion succeeds");

    let captured = received.recv().expect("request captured");
    assert_eq!(captured.header("cookie"), None);
}

/// A build with no premium host must stay on the free tier even when credentials exist, rather
/// than attaching one to a request bound for the free endpoint.
#[test]
fn without_a_premium_host_no_credential_is_attached() {
    let (free_endpoint, received) = serve(REPLY);
    let config = config_for(&free_endpoint);
    let egress = Egress::new();
    let mut sink = RecordingSink::new();
    let mut policy = Policy::begin(
        routing(),
        ReleasePlan::new(),
        CapabilitySet::from_iter([Capability::WebFetch]),
        &mut sink,
    )
    .expect("policy");

    let mut subscription = StubSubscription { remaining: 5 };
    let mut client = AichatClient::new(&config, &egress).with_subscription(&mut subscription);
    let request = ChatRequest::new("automatic", vec![Message::user("hi")]);
    client
        .complete(&mut policy, &request)
        .expect("completion succeeds");

    let captured = received.recv().expect("request captured");
    assert_eq!(captured.header("cookie"), None);
    // The credential must not have been spent either, since it was never usable here.
    assert_eq!(subscription.remaining, 5);
}
