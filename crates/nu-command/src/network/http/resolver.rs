use std::{
    error, fmt, io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
};

use http::Uri;
use ureq::{
    config::Config,
    unversioned::resolver::{ArrayVec, ResolvedSocketAddrs, Resolver},
    unversioned::transport::NextTimeout,
};

#[derive(Debug)]
pub struct DnsLookupResolver;

impl Resolver for DnsLookupResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().unwrap_or("");
        // Determine the port: use explicit port if provided, otherwise derive from scheme
        let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
            Some("https") => 443,
            _ => 80, // http commands only support HTTP/HTTPS, default to port 80
        });

        // Resolve using ToSocketAddrs which correctly handles all address
        // formats including bracketed IPv6 literals like "[::1]:8002".
        let addr = format!("{host}:{port}");
        let addrs = match addr.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(_) => {
                // Re-resolve through getaddrinfo to get a specific LookupErrorKind
                // (NoName, Again, etc.) for better error messages.
                return Err(ureq::Error::Other(Box::new(
                    getaddrinfo_error(host, port),
                )));
            }
        };

        let ip_family = config.ip_family();
        let mut resolved = self.empty();
        let capacity = array_vec_capacity(&resolved);
        for sockaddr in addrs {
            // ToSocketAddrs already sets the port, but ensure it via set_port
            // for consistency with the port we derived from the URI.
            let sockaddr = set_port(sockaddr, port);
            // Filter addresses based on configured IP family (IPv4 only, IPv6 only, or any)
            let is_wanted = match ip_family {
                ureq::config::IpFamily::Any => true,
                ureq::config::IpFamily::Ipv4Only => sockaddr.is_ipv4(),
                ureq::config::IpFamily::Ipv6Only => sockaddr.is_ipv6(),
            };
            if is_wanted {
                resolved.push(sockaddr);
                // ArrayVec has a fixed capacity, stop when full
                if resolved.len() >= capacity {
                    break;
                }
            }
        }

        Ok(resolved)
    }
}

/// Re-resolve via dns_lookup::getaddrinfo to get a detailed LookupError
/// with a specific error kind (NoName, Again, Fail, etc.).
fn getaddrinfo_error(host: &str, port: u16) -> LookupError {
    // Strip brackets from IPv6 literals since getaddrinfo doesn't accept them.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match dns_lookup::getaddrinfo(Some(host), None, None) {
        Err(err) => LookupError(err),
        Ok(iter) => {
            // getaddrinfo succeeded but ToSocketAddrs failed — shouldn't happen,
            // but consume the iterator and produce the first error if any.
            for result in iter {
                if let Err(err) = result {
                    return LookupError(dns_lookup::LookupError::from(err));
                }
            }
            // Both succeeded somehow — produce a generic IO error.
            LookupError(dns_lookup::LookupError::from(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to resolve {host}:{port}"),
            )))
        }
    }
}

/// Set the port on a SocketAddr
fn set_port(addr: SocketAddr, port: u16) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), port)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
            *v6.ip(),
            port,
            v6.flowinfo(),
            v6.scope_id(),
        )),
    }
}

/// Extract the capacity of an ArrayVec at compile time.
fn array_vec_capacity<T, const N: usize>(_: &ArrayVec<T, N>) -> usize {
    N
}

#[derive(Debug)]
pub struct LookupError(pub dns_lookup::LookupError);

impl Clone for LookupError {
    fn clone(&self) -> Self {
        Self(dns_lookup::LookupError::new(self.0.error_num()))
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lookup_error = self.clone();
        let io_error = io::Error::from(lookup_error.0);
        fmt::Display::fmt(&io_error, f)
    }
}

impl error::Error for LookupError {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

    #[test]
    fn to_socket_addrs_handles_bracketed_ipv6() {
        // This is the core invariant: ToSocketAddrs correctly parses
        // bracketed IPv6 from http::Uri::host() combined with a port,
        // which getaddrinfo cannot do.
        let addrs: Vec<_> = "[::1]:8002".to_socket_addrs().unwrap().collect();
        assert_eq!(addrs[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addrs[0].port(), 8002);
    }

    #[test]
    fn to_socket_addrs_handles_ipv4() {
        let addrs: Vec<_> = "127.0.0.1:9090".to_socket_addrs().unwrap().collect();
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addrs[0].port(), 9090);
    }

    #[test]
    fn to_socket_addrs_handles_hostname() {
        let addrs: Vec<_> = "localhost:3000".to_socket_addrs().unwrap().collect();
        assert_eq!(addrs[0].port(), 3000);
    }
}
