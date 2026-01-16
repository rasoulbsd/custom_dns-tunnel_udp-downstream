use rand::Rng;
use std::net::UdpSocket;

pub fn get_random_port() -> u16 {
    let mut rng = rand::thread_rng();
    // Use ports in the range 49152-65535 (dynamic/private ports)
    rng.gen_range(49152..=65535)
}

pub fn bind_random_port(addr: &str) -> std::io::Result<UdpSocket> {
    let mut attempts = 0;
    loop {
        let port = get_random_port();
        let bind_addr = format!("{}:{}", addr, port);
        
        match UdpSocket::bind(&bind_addr) {
            Ok(socket) => return Ok(socket),
            Err(_) => {
                attempts += 1;
                if attempts > 100 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "Failed to find available port after 100 attempts",
                    ));
                }
            }
        }
    }
}

pub fn rotate_resolver<T>(resolvers: &[T], index: usize) -> &T {
    &resolvers[index % resolvers.len()]
}
