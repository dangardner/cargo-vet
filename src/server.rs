use hyper::service::{make_service_fn, service_fn};
use hyper::{http::Error, server::conn::AddrStream, Body, Request, Response, Server, StatusCode};
use serde::Serialize;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::CriteriaEntry;
use crate::cli::ServerArgs;
use crate::format::{AuditEntry, WildcardEntry};
use crate::storage::Store;

#[derive(Serialize)]
pub struct AuditDump<'a> {
    /// Vec of normal audits
    pub normal_audits: &'a Vec<&'a AuditEntry>,
    /// Vec of wildcard audits
    pub wildcard_audits: &'a Vec<&'a WildcardEntry>,
    /// Map of criteria
    pub criteria: &'a BTreeMap<String, CriteriaEntry>,
}

async fn handle(
    store: Arc<Store>,
    addr: IpAddr,
    req: Request<Body>,
    use_x_forwarded_for: bool,
) -> Result<Response<Body>, Error> {
    let mut addr = addr;
    if use_x_forwarded_for && req.headers().contains_key("X-Forwarded-For") {
        if let Some(headervalue) = req.headers().get("X-Forwarded-For") {
            if let Ok(s) = headervalue.to_str() {
                let s = s.split(' ').last().unwrap();
                if let Ok(ip) = s.parse() {
                    addr = ip;
                }
            }
        }
    }
    // Log the request
    println!("{} {} {}", addr, req.method(), req.uri());

    let path_chunks: Vec<_> = req.uri().path().split('/').collect();
    if path_chunks.len() < 2 {
        return not_found();
    }
    match path_chunks[1] {
        "crates" => serve_audits(store, path_chunks),
        "criteria" => serve_criteria(store, path_chunks),
        _ => not_found(),
    }
}

fn serve_audits(
    store: Arc<Store>,
    path_chunks: Vec<&str>,
) -> Result<hyper::Response<hyper::Body>, hyper::http::Error> {
    if path_chunks.len() != 3 {
        return not_found();
    }
    let package = path_chunks[2];

    // Iterator over every audits file, including imported audits.
    let all_audits_files = store.imported_audits().values().chain([&store.audits]);

    // Iterator over every normal audit.
    let all_audits = all_audits_files.clone().flat_map(|audits_file| {
        audits_file
            .audits
            .get(package)
            .map(|v| &v[..])
            .unwrap_or(&[])
    });

    // Iterator over every wildcard audit.
    let all_wildcard_audits = all_audits_files.clone().flat_map(|audits_file| {
        audits_file
            .wildcard_audits
            .get(package)
            .map(|v| &v[..])
            .unwrap_or(&[])
    });

    let mut criteria = store.audits.criteria.clone();
    criteria.append(&mut default_criteria());

    let s = serde_json::to_string(&AuditDump {
        normal_audits: &all_audits.collect(),
        wildcard_audits: &all_wildcard_audits.collect(),
        criteria: &criteria,
    })
    .unwrap();
    Ok(Response::new(Body::from(s)))
}

fn default_criteria() -> BTreeMap<String, CriteriaEntry> {
    let mut default_criteria = BTreeMap::new(); 
    default_criteria.insert("safe-to-run".to_string(), CriteriaEntry {
        description: Some("This crate can be compiled, run, and tested on a local workstation or in
controlled automation without surprising consequences, such as:
* Reading or writing data from sensitive or unrelated parts of the filesystem.
* Installing software or reconfiguring the device.
* Connecting to untrusted network endpoints.
* Misuse of system resources (e.g. cryptocurrency mining).".to_string()),
        description_url: None,
        implies: vec!(),
        aggregated_from: vec!(),
    });
    default_criteria.insert("safe-to-deploy".to_string(), CriteriaEntry {
        description: Some("This crate will not introduce a serious security vulnerability to production
software exposed to untrusted input.

Auditors are not required to perform a full logic review of the entire crate.
Rather, they must review enough to fully reason about the behavior of all unsafe
blocks and usage of powerful imports. For any reasonable usage of the crate in
real-world software, an attacker must not be able to manipulate the runtime
behavior of these sections in an exploitable or surprising way.

Ideally, all unsafe code is fully sound, and ambient capabilities (e.g.
filesystem access) are hardened against manipulation and consistent with the
advertised behavior of the crate. However, some discretion is permitted. In such
cases, the nature of the discretion should be recorded in the `notes` field of
the audit record.

For crates which generate deployed code (e.g. build dependencies or procedural
macros), reasonable usage of the crate should output code which meets the above
criteria.".to_string()),
        description_url: None,
        implies: vec!("safe-to-run".to_owned().into()),
        aggregated_from: vec!(),
    });
    default_criteria
}


fn serve_criteria(
    store: Arc<Store>,
    _path_chunks: Vec<&str>,
) -> Result<hyper::Response<hyper::Body>, hyper::http::Error> {
    let mut criteria = store.audits.criteria.clone();
    criteria.append(&mut default_criteria());
    let s = serde_json::to_string(&criteria).unwrap();
    Ok(Response::new(Body::from(s)))
}

fn not_found() -> Result<hyper::Response<hyper::Body>, hyper::http::Error> {
    return Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from(""));
}

pub async fn start_server(store: Arc<Store>, sub_args: &ServerArgs, use_x_forwarded_for: bool) {
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

        let service = service_fn(move |req| handle(store.clone(), addr, req, use_x_forwarded_for));

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