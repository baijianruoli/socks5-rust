extern crate core;

use std::io::{Read, Write};

fn do_greeting(src_reader: &mut std::net::TcpStream,
               src_writer: &mut std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = vec![0x00; 256];
    // 读一个byte
    src_reader.read_exact(&mut buf[0..1])?;
    // 判断是否是socks5协议的版本号
    if buf[0] != 0x05 {
        panic!("unreachable!");
    }

    src_reader.read_exact(&mut buf[0..1])?;
    let nauth = buf[0] as usize;
    src_reader.read_exact(&mut buf[0..nauth])?;

    // buf[0..nauth]) must contains 0x00

    src_writer.write(&[0x05])?;
    src_writer.write(&[0x00])?;

    println!("greeting done");

    Ok(())
}

// 解析出请求的目标地址
fn parse_dst(src_reader: &mut std::net::TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = vec![0x00; 256];
    src_reader.read_exact(&mut buf[0..1])?;
    // 判断是否是socks5协议的版本号
    if buf[0] != 0x05 {
        panic!("unreachable!");
    }
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x01 {
        // 不支持0x01以外的SOCK命令码，0x01表示CONNECT请求
        panic!("unreachable!");
    }
    src_reader.read_exact(&mut buf[0..1])?;
    if buf[0] != 0x00 {
        panic!("unreachable!");
    }

    src_reader.read_exact(&mut buf[0..1])?;
    // 匹配ATYP BND.ADDR类型
    let host = match buf[0] {
        0x01 => {
            // IPv4地址，DST.ADDR部分4字节长度
            src_reader.read_exact(&mut buf[0..4])?;
            std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).to_string()
        }
        0x03 => {
            // 域名，DST.ADDR部分第一个字节为域名长度，DST.ADDR剩余的内容为域名，没有\0结尾
            src_reader.read_exact(&mut buf[0..1])?;
            let l = buf[0] as usize;
            src_reader.read_exact(&mut buf[0..l])?;
            String::from_utf8_lossy(&buf[0..l]).to_string()  // example: baidu.com
        }
        0x04 => {
            // IPv6地址，16个字节长度
            src_reader.read_exact(&mut buf[0..16])?;
            std::net::Ipv6Addr::new(
                ((buf[0x00] as u16) << 8) | (buf[0x01] as u16),
                ((buf[0x02] as u16) << 8) | (buf[0x03] as u16),
                ((buf[0x04] as u16) << 8) | (buf[0x05] as u16),
                ((buf[0x06] as u16) << 8) | (buf[0x07] as u16),
                ((buf[0x08] as u16) << 8) | (buf[0x09] as u16),
                ((buf[0x0a] as u16) << 8) | (buf[0x0b] as u16),
                ((buf[0x0c] as u16) << 8) | (buf[0x0d] as u16),
                ((buf[0x0e] as u16) << 8) | (buf[0x0f] as u16),
            ).to_string()
        }
        _ => panic!("unreachable!")
    };

    src_reader.read_exact(&mut buf[0..2])?;
    let port = ((buf[0] as u16) << 8) | (buf[1] as u16);
    let dst = format!("{}:{}", host, port);

    Ok(dst)
}

// socks5协议维基百科：https://zh.m.wikipedia.org/zh-hans/SOCKS
// 英文：https://en.wikipedia.org/wiki/SOCKS#SOCKS5
fn handle(src_stream: &std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("src: {}", src_stream.peer_addr().unwrap());
    let mut src_reader = src_stream.try_clone()?;
    let mut src_writer = src_stream.try_clone()?;
    do_greeting(&mut src_reader, &mut src_writer)?;
    let dst = parse_dst(&mut src_reader)?;
    println!("dst: {}", dst);

    // 连接目标地址，转发请求并返回响应
    let dst_stream = std::net::TcpStream::connect(&dst)?;
    let mut dst_reader = dst_stream.try_clone()?;
    let mut dst_writer = dst_stream.try_clone()?;

    // 参考socks5对响应包的描述
    // VER
    src_writer.write(&[0x05])?;
    // STATUS
    src_writer.write(&[0x00])?;
    // RSV
    src_writer.write(&[0x00])?;
    // BNDADDR
    src_writer.write(&[0x01])?;
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;
    // BNDPORT
    src_writer.write(&[0x00])?;
    src_writer.write(&[0x00])?;

    std::thread::spawn(move || {
        std::io::copy(&mut src_reader, &mut dst_writer).ok();
    });
    std::io::copy(&mut dst_reader, &mut src_writer).ok();

    Ok(())
}

fn main() {
    let mut c_listen = String::from("127.0.0.1:1080");
    {
        let mut ap = argparse::ArgumentParser::new();
        ap.set_description("Socks5 Proxy");
        // 定义支持的参数
        ap.refer(&mut c_listen).add_option(
            &["-l", "--listen"], argparse::Store, "listen address",
        );
        ap.parse_args_or_exit();
    }

    println!("Listen and server on {}", c_listen);

    // 开启tcp监听器
    let listener = std::net::TcpListener::bind(c_listen.as_str()).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(data) => {
                // 创建新的线程去处理请求
                std::thread::spawn(move || {
                    if let Err(err) = handle(&data) {
                        println!("error: {:?}", err)
                    }
                });
            }
            Err(err) => {
                println!("error: {:?}", err);
            }
        }
    }
}
