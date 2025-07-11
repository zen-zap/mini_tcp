use std::thread;
use std::io;
use std::io::prelude::*;

fn main() -> io::Result<()> {
    let mut i = mini_tcp::Interface::new()?;
    eprintln!("created  interface");
    let mut l1 = i.bind(8000)?;    
    while let Ok(mut stream) = l1.accept()
    {
        eprintln!("got connection!");
        thread::spawn(move || {
            stream.write(b" it works!\n").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap(); // we're now gonna do this manually
            loop {
                let mut buf=[0u8; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n==0
                {
                    eprintln!("no more data -- the other side hung up");
                    break;
                }
                else {
                    println!("got {} from the other side", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }
    Ok(())
}
