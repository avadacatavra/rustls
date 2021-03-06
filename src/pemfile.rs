use std::io;
use base64;
use key;
fn extract<A>(rd: &mut io::BufRead,
              start_mark: &str,
              end_mark: &str,
              f: &Fn(Vec<u8>) -> A) -> Result<Vec<A>, ()> {
  let mut ders = Vec::new();
  let mut b64buf = String::new();
  let mut take_base64 = false;

  let mut raw_line = Vec::<u8>::new();
  loop {
    raw_line.clear();
    let len = try!(rd.read_until(b'\n', &mut raw_line)
                   .map_err(|_| ()));

    if len == 0 {
      return Ok(ders);
    }
    let line = String::from_utf8_lossy(&raw_line);

    if line.starts_with(start_mark) {
      take_base64 = true;
      continue;
    }

    if line.starts_with(end_mark) {
      take_base64 = false;
      let der = try!(base64::decode_ws(&b64buf)
                     .map_err(|_| ()));
      ders.push(f(der));
      b64buf = String::new();
      continue;
    }

    if take_base64 {
      b64buf.push_str(&line.trim());
    }
  }
}


/// Extract all the certificates from rd, and return a vec of bytevecs
/// containing the der-format contents.
pub fn certs(rd: &mut io::BufRead) -> Result<Vec<key::Certificate>, ()> {
  extract(rd,
          "-----BEGIN CERTIFICATE-----",
          "-----END CERTIFICATE-----",
          &|v| key::Certificate(v))
}

/// Extract all RSA private keys from rd, and return a vec of bytevecs
/// containing the der-format contents.
pub fn rsa_private_keys(rd: &mut io::BufRead) -> Result<Vec<key::PrivateKey>, ()> {
  extract(rd,
          "-----BEGIN RSA PRIVATE KEY-----",
          "-----END RSA PRIVATE KEY-----",
          &|v| key::PrivateKey(v))
}
