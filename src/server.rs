use hyper::service::{make_service_fn, service_fn};
use hyper::{http::Error, server::conn::AddrStream, Body, Request, Response, Server, StatusCode};
use serde::Serialize;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::cli::ServerArgs;
use crate::format::{AuditEntry, WildcardEntry};
use crate::storage::Store;

#[derive(Serialize)]
pub struct AuditDump<'a> {
    /// Vec of normal audits
    pub normal_audits: &'a Vec<&'a AuditEntry>,
    /// Vec of wildcard audits
    pub wildcard_audits: &'a Vec<&'a WildcardEntry>,
}

async fn handle(
    store: Arc<Store>,
    addr: IpAddr,
    req: Request<Body>,
) -> Result<Response<Body>, Error> {
    let path_chunks: Vec<_> = req.uri().path().split("/").collect();
    if path_chunks.len() != 3 || path_chunks[1] != "crates" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(""));
    }
    let package = path_chunks[2];

    // Log the request
    println!("{} {} {}", addr, req.method(), req.uri());

    // Iterator over every audits file, including imported audits.
    let all_audits_files = store
        .imported_audits()
        .values()
        .enumerate()
        .map(|(_import_index, audits_file)| audits_file)
        .chain([&store.audits]);

    // Iterator over every normal audit.
    let all_audits: Vec<_> = all_audits_files
        .clone()
        .into_iter()
        .flat_map(|audits_file| {
            audits_file
                .audits
                .get(package)
                .map(|v| &v[..])
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(move |(_audit_index, audit)| audit)
                .collect::<Vec<_>>()
        })
        .collect();

    // Iterator over every wildcard audit.
    let all_wildcard_audits: Vec<_> = all_audits_files
        .clone()
        .into_iter()
        .flat_map(|audits_file| {
            audits_file
                .wildcard_audits
                .get(package)
                .map(|v| &v[..])
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(move |(_audit_index, audit)| audit)
                .collect::<Vec<_>>()
        })
        .collect();

    let s = serde_json::to_string(&AuditDump {
        normal_audits: &all_audits,
        wildcard_audits: &all_wildcard_audits,
    })
    .unwrap();
    Ok(Response::new(Body::from(s)))
}

pub async fn start_server(store: Arc<Store>, sub_args: &ServerArgs) {
    // Construct our SocketAddr to listen on...
    let ip: IpAddr = sub_args
        .listen_addr
        .parse()
        .expect("Invalid listen address");
    let addr = SocketAddr::from((ip, sub_args.listen_port));

    let make_service = make_service_fn(move |conn: &AddrStream| {
        // Have to clone here to use with each invocation
        let store = store.clone();
        let addr = conn.remote_addr().ip();

        let service = service_fn(move |req| handle(store.clone(), addr, req));

        // Return the service to hyper.
        async move { Ok::<_, Infallible>(service) }
    });

    // Then bind and serve...
    let server = Server::bind(&addr).serve(make_service);
    println!("Listening on {}", addr);

    // And run forever...
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}