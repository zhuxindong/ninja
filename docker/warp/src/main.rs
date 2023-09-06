use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn print_help(program_name: &str) {
    eprintln!(
        "Usage: {} [--listen LISTEN_ADDR] --target TARGET_ADDR",
        program_name
    );
    eprintln!("Options:");
    eprintln!("  -l, --listen    Address and port to listen on. Default: 127.0.0.1:9999");
    eprintln!("  -t, --target    Target address and port to forward to. (required)");
    eprintln!("  -h, --help      Print this help message.");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "127.0.0.1:9999".to_string();
    let mut target_addr = String::new();

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--listen" | "-l" => {
                if idx + 1 < args.len() {
                    listen_addr = args[idx + 1].clone();
                    idx += 2;
                } else {
                    eprintln!(
                        "Error: '--listen' requires an address. Use '--help' for more information."
                    );
                    print_help(&args[0]);
                    return Ok(());
                }
            }
            "--target" | "-t" => {
                if idx + 1 < args.len() {
                    target_addr.push_str(&args[idx + 1]);
                    idx += 2;
                } else {
                    eprintln!(
                        "Error: '--target' requires an address. Use '--help' for more information."
                    );
                    print_help(&args[0]);
                    return Ok(());
                }
            }
            "--help" | "-h" => {
                print_help(&args[0]);
                return Ok(());
            }
            _ => {
                eprintln!(
                    "Error: Unknown argument '{}'. Use '--help' for more information.",
                    args[idx]
                );
                print_help(&args[0]);
                return Ok(());
            }
        }
    }

    if target_addr.is_empty() {
        eprintln!("Error: '--target' must be set. Use '--help' for more information.");
        return Ok(());
    }

    // 现在你可以使用listen_addr和target_addr了
    println!("Listening on: {}", listen_addr);
    println!("Forwarding to: {}", target_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        match listener.accept().await {
            Ok((src, _)) => {
                tokio::spawn(handle_client(src, target_addr.clone()));
            }
            Err(e) => {
                println!("Accept error: {:?}", e);
            }
        }
    }
}

async fn handle_client(mut src: TcpStream, target_addr: String) {
    match TcpStream::connect(target_addr).await {
        Ok(mut dst) => {
            let (mut src_reader, mut src_writer) = src.split();
            let (mut dst_reader, mut dst_writer) = dst.split();

            let src_to_dst = async {
                let mut buf = vec![0u8; 4096];
                loop {
                    match src_reader.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if dst_writer.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            };

            let dst_to_src = async {
                let mut buf = vec![0u8; 4096];
                loop {
                    match dst_reader.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if src_writer.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            };

            let _ = tokio::join!(src_to_dst, dst_to_src);
        }
        Err(_) => {
            println!("Failed to connect to the target.");
        }
    }
}
