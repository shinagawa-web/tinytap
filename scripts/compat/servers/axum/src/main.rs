use axum::{
    body::Bytes,
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::path::PathBuf;

fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../testdata")
}

fn content_type_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        _ => "text/plain",
    }
}

async fn hello() -> &'static str {
    "Hello, world"
}

async fn serve_file(Path(name): Path<String>) -> Response {
    // :name is a single path segment (axum's router never lets it contain a
    // '/'), but a literal ".." segment would still climb out of testdata/.
    if name.contains("..") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let path = testdata_dir().join(&name);
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let content_type = content_type_for(&path);
            ([(header::CONTENT_TYPE, content_type)], Bytes::from(bytes)).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let app = Router::new()
        .route("/hello", get(hello))
        .route("/:name", get(serve_file));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap();
    println!("listening on :{port}");
    axum::serve(listener, app).await.unwrap();
}
