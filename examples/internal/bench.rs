// This program does assorted benchmarking of rustls.
//
// Note: we don't use any of the standard 'cargo bench', 'test::Bencher',
// etc. because it's unstable at the time of writing.

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::fs;
use std::io::{self, Write};
use std::fs::File;
use std::path::Path;
use std::io::Read;
use std::error::Error;

extern crate rustls;
use rustls::{ClientConfig, ClientSession};
use rustls::{ServerConfig, ServerSession};
use rustls::ServerSessionMemoryCache;
use rustls::ClientSessionMemoryCache;
use rustls::Session;
use rustls::Ticketer;
use rustls::internal::pemfile;
use rustls::internal::msgs::enums::SignatureAlgorithm;

//FIXME don't c/p common from tests to example
mod common;
use common::TlsClient;

fn connect(hostname: &str) -> TlsClient {
    TlsClient::new(hostname)
}

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

fn _bench<Fsetup, Ftest, S>(count: usize, name: &'static str, f_setup: Fsetup, f_test: Ftest)
    where Fsetup: Fn() -> S,
          Ftest: Fn(S)
{
    let mut times = Vec::new();

    for _ in 0..count {
        let state = f_setup();
        let start = Instant::now();
        f_test(state);
        times.push(duration_nanos(Instant::now().duration_since(start)));
    }

    println!("{}", name);
    println!("{:?}", times);
}

fn time<F>(mut f: F) -> f64
    where F: FnMut()
{
    let start = Instant::now();
    f();
    let end = Instant::now();
    let dur = duration_nanos(end.duration_since(start));
    dur as f64
}

fn transfer(left: &mut Session, right: &mut Session) {
    let mut buf = [0u8; 262144];

    while left.wants_write() {
        let sz = left.write_tls(&mut buf.as_mut()).unwrap();
        if sz == 0 {
            return;
        }

        let mut offs = 0;
        loop {
            offs += right.read_tls(&mut buf[offs..sz].as_ref()).unwrap();
            if sz == offs {
                break;
            }
        }
    }
}

fn drain(d: &mut Session, expect_len: usize) {
    let mut left = expect_len;
    let mut buf = [0u8; 8192];
    loop {
        let sz = d.read(&mut buf).unwrap();
        left -= sz;
        if left == 0 {
            break;
        }
    }
}

fn get_chain() -> Vec<rustls::Certificate> {
    pemfile::certs(&mut io::BufReader::new(fs::File::open("test-ca/rsa/end.fullchain").unwrap()))
        .unwrap()
}

fn get_key() -> rustls::PrivateKey {
    pemfile::rsa_private_keys(&mut io::BufReader::new(fs::File::open("test-ca/rsa/end.rsa")
                .unwrap()))
            .unwrap()[0]
        .clone()
}

#[derive(PartialEq, Clone)]
enum ClientAuth {
    No,
    Yes,
}

#[derive(PartialEq, Clone)]
enum Resumption {
    No,
    SessionID,
    Tickets,
}

impl Resumption {
    fn label(&self) -> &'static str {
        match *self {
            Resumption::No => "no-resume",
            Resumption::SessionID => "sessionid",
            Resumption::Tickets => "tickets",
        }
    }
}

fn make_server_config(version: rustls::ProtocolVersion,
                      clientauth: &ClientAuth,
                      resume: &Resumption)
                      -> ServerConfig {
    let mut cfg = ServerConfig::new();

    cfg.set_single_cert(get_chain(), get_key());

    if clientauth == &ClientAuth::Yes {
        cfg.set_client_auth_roots(get_chain(), true);
    }

    if resume == &Resumption::SessionID {
        cfg.set_persistence(ServerSessionMemoryCache::new(128));
    } else if resume == &Resumption::Tickets {
        cfg.ticketer = Ticketer::new();
    }

    cfg.versions.clear();
    cfg.versions.push(version);

    cfg
}

fn make_client_config(version: rustls::ProtocolVersion,
                      suite: &'static rustls::SupportedCipherSuite,
                      clientauth: &ClientAuth,
                      resume: &Resumption)
                      -> ClientConfig {
    let mut cfg = ClientConfig::new();
    let mut rootbuf = io::BufReader::new(fs::File::open("test-ca/rsa/ca.cert").unwrap());
    cfg.root_store.add_pem_file(&mut rootbuf).unwrap();
    cfg.ciphersuites.clear();
    cfg.ciphersuites.push(suite);
    cfg.versions.clear();
    cfg.versions.push(version);

    if clientauth == &ClientAuth::Yes {
        cfg.set_single_client_cert(get_chain(), get_key());
    }

    if resume != &Resumption::No {
        cfg.set_persistence(ClientSessionMemoryCache::new(128));
    }

    cfg
}

fn bench_handshake(version: rustls::ProtocolVersion,
                   suite: &'static rustls::SupportedCipherSuite,
                   clientauth: ClientAuth,
                   resume: Resumption) {
    let client_config = Arc::new(make_client_config(version, suite, &clientauth, &resume));
    let server_config = Arc::new(make_server_config(version, &clientauth, &resume));

    if !suite.usable_for_version(version) {
        return;
    }

    let rounds = 512;
    let mut client_time = 0f64;
    let mut server_time = 0f64;

    for _ in 0..rounds {
        let mut client = ClientSession::new(&client_config, "localhost");
        let mut server = ServerSession::new(&server_config);

        server_time += time(|| {
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap()
        });
        client_time += time(|| {
            transfer(&mut server, &mut client);
            client.process_new_packets().unwrap()
        });
        server_time += time(|| {
            transfer(&mut client, &mut server);
            server.process_new_packets().unwrap()
        });
        client_time += time(|| {
            transfer(&mut server, &mut client);
            client.process_new_packets().unwrap()
        });
    }

    println!("handshakes\t{:?}\t{:?}\tclient\t{}\t{}\t{:.2}\thandshake/s",
             version,
             suite.suite,
             if clientauth == ClientAuth::Yes {
                 "mutual"
             } else {
                 "server-auth"
             },
             resume.label(),
             rounds as f64 / client_time);
    println!("handshakes\t{:?}\t{:?}\tserver\t{}\t{}\t{:.2}\thandshake/s",
             version,
             suite.suite,
             if clientauth == ClientAuth::Yes {
                 "mutual"
             } else {
                 "server-auth"
             },
             resume.label(),
             rounds as f64 / server_time);
}

fn do_handshake(client: &mut ClientSession, server: &mut ServerSession) {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets().unwrap();
        transfer(server, client);
        client.process_new_packets().unwrap();
    }
}

fn bench_bulk(version: rustls::ProtocolVersion, suite: &'static rustls::SupportedCipherSuite) {
    let client_config =
        Arc::new(make_client_config(version, suite, &ClientAuth::No, &Resumption::No));
    let server_config = Arc::new(make_server_config(version, &ClientAuth::No, &Resumption::No));

    if !suite.usable_for_version(version) {
        return;
    }

    let mut client = ClientSession::new(&client_config, "localhost");
    let mut server = ServerSession::new(&server_config);

    do_handshake(&mut client, &mut server);

    let mut buf = Vec::new();
    buf.resize(1024 * 1024, 0u8);

    let total_mb = 512;
    let mut time_send = 0f64;
    let mut time_recv = 0f64;

    for _ in 0..total_mb {
        time_send += time(|| {
            server.write_all(&buf).unwrap();
            ()
        });
        time_recv += time(|| {
            transfer(&mut server, &mut client);
            client.process_new_packets().unwrap()
        });
        drain(&mut client, buf.len());
    }

    println!("bulk\t{:?}\t{:?}\tsend\t{:.2}\tMB/s",
             version,
             suite.suite,
             total_mb as f64 / time_send);
    println!("bulk\t{:?}\t{:?}\trecv\t{:.2}\tMB/s",
             version,
             suite.suite,
             total_mb as f64 / time_recv);
}

fn website_bench() {
    let mut file = match File::open(Path::new("./examples/internal/sites.txt")) {
        Err(e) => return,   //fail silently
        Ok(file) => file,
    };

    let mut sites = String::new();
    file.read_to_string(&mut sites).unwrap();

    let mut times = vec!();
    //let mut connect_times = vec!();
    for line in sites.lines(){
        let l: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
        let site = l[0].trim();
        let expected = l[1].trim();

        // separate out client creation -- tried and resulted in
        //  Average client creation time: 0.00000007058823529411766
        //let start = Instant::now();
        //let mut client = connect(site);
        //connect_times.push(duration_nanos(Instant::now().duration_since(start)));

        let start = Instant::now();
        connect(site)
            .expect(expected)
            .go()
            .unwrap();
        times.push(duration_nanos(Instant::now().duration_since(start)));
    }
    println!("{:?}", times);

    //let avg = connect_times.iter().fold(0.0, |a, &b| a + b)/(connect_times.len() as f64);
    //println!("Average client creation time: {}", avg );

}

fn main() {
    website_bench();
    /*for version in &[rustls::ProtocolVersion::TLSv1_3, rustls::ProtocolVersion::TLSv1_2] {
        for suite in &rustls::ALL_CIPHERSUITES {
            if suite.sign == SignatureAlgorithm::ECDSA {
                // TODO: Need ECDSA server support for this.
                continue;
            }

            bench_bulk(*version, suite);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::No);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::No);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::SessionID);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::SessionID);
            bench_handshake(*version, suite, ClientAuth::No, Resumption::Tickets);
            bench_handshake(*version, suite, ClientAuth::Yes, Resumption::Tickets);
        }
    }*/
}
