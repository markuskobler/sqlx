use std::io::{self, Read, Write};

use crate::io::ReadBuf;
use crate::net::tls::util::StdSocket;
use crate::net::tls::TlsConfig;
use crate::net::Socket;
use crate::rt;
use crate::Error;

use native_tls::{HandshakeError, Identity};
use std::task::{Context, Poll};

pub struct NativeTlsSocket<S: Socket> {
    stream: native_tls::TlsStream<StdSocket<S>>,
}

impl<S: Socket> Socket for NativeTlsSocket<S> {
    fn try_read(&mut self, buf: &mut dyn ReadBuf) -> io::Result<usize> {
        self.stream.read(buf.init_mut())
    }

    fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.get_mut().poll_ready(cx)
    }

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.get_mut().poll_ready(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.stream.shutdown() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.stream.get_mut().poll_ready(cx),
            ready => Poll::Ready(ready),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NativeTlsConnector {
    connector: native_tls::TlsConnector,
}

pub async fn connector(config: TlsConfig<'_>) -> crate::Result<NativeTlsConnector> {
    // native-tls reloads Android's system roots even when built-in roots are disabled.
    if cfg!(target_os = "android")
        && !cfg!(feature = "_tls-native-tls-roots")
        && !config.accept_invalid_certs
    {
        return Err(Error::Configuration(
            "native-tls cannot disable Android's system roots; enable `tls-native-tls-roots` \
             or use rustls to trust only supplied CA certificates"
                .into(),
        ));
    }

    let mut builder = native_tls::TlsConnector::builder();

    builder
        .disable_built_in_roots(!cfg!(feature = "_tls-native-tls-roots"))
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .danger_accept_invalid_hostnames(config.accept_invalid_hostnames);

    if let Some(root_cert_path) = config.root_cert_path {
        let data = root_cert_path.data().await?;
        builder.add_root_certificate(native_tls::Certificate::from_pem(&data).map_err(Error::tls)?);
    }

    // authentication using user's key-file and its associated certificate
    if let (Some(cert_path), Some(key_path)) = (config.client_cert_path, config.client_key_path) {
        let cert_path = cert_path.data().await?;
        let key_path = key_path.data().await?;
        let identity = Identity::from_pkcs8(&cert_path, &key_path).map_err(Error::tls)?;
        builder.identity(identity);
    }

    // The openssl TlsConnector synchronously loads certificates from files.
    // Loading these files can block for tens of milliseconds.
    let connector = rt::spawn_blocking(move || builder.build())
        .await
        .map_err(Error::tls)?;
    Ok(NativeTlsConnector { connector })
}

pub async fn handshake<S: Socket>(
    socket: S,
    hostname: &str,
    connector: &NativeTlsConnector,
) -> crate::Result<NativeTlsSocket<S>> {
    let mut mid_handshake = match connector
        .connector
        .connect(hostname, StdSocket::new(socket))
    {
        Ok(tls_stream) => return Ok(NativeTlsSocket { stream: tls_stream }),
        Err(HandshakeError::Failure(e)) => return Err(Error::tls(e)),
        Err(HandshakeError::WouldBlock(mid_handshake)) => mid_handshake,
    };

    loop {
        mid_handshake.get_mut().ready().await?;

        match mid_handshake.handshake() {
            Ok(tls_stream) => return Ok(NativeTlsSocket { stream: tls_stream }),
            Err(HandshakeError::Failure(e)) => return Err(Error::tls(e)),
            Err(HandshakeError::WouldBlock(mid_handshake_)) => {
                mid_handshake = mid_handshake_;
            }
        }
    }
}

#[cfg(all(test, any(feature = "_rt-tokio", feature = "_rt-async-io")))]
mod tests {
    use super::*;

    #[test]
    fn certificate_verification_respects_root_features() {
        for accept_invalid_hostnames in [false, true] {
            let result = rt::test_block_on(connector(TlsConfig {
                accept_invalid_certs: false,
                accept_invalid_hostnames,
                root_cert_path: None,
                client_cert_path: None,
                client_key_path: None,
            }));

            if cfg!(target_os = "android") && !cfg!(feature = "_tls-native-tls-roots") {
                let Error::Configuration(error) = result.unwrap_err() else {
                    panic!("expected a configuration error");
                };
                assert!(error.to_string().contains("tls-native-tls-roots"));
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn accepting_invalid_certificates_does_not_require_roots() {
        rt::test_block_on(connector(TlsConfig {
            accept_invalid_certs: true,
            accept_invalid_hostnames: true,
            root_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }))
        .unwrap();
    }
}
