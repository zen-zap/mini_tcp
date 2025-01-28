use std::io::prelude::*;
use std::io;
use std::collections::HashMap;
use std::thread;
use std::sync::{Arc, Mutex, Condvar}; 
// NOTE: read about mpsc channels -- multiple producer single consumer
// NOTE: read about Mutex, Arc, Condvar again
use std::collections::{VecDeque, hash_map::Entry};
// get a recap about Arc, Mutex, Condvar
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub struct Quad
{
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

/// # Connection Manager<br>
/// ### *parameters*: connections, terminate, pending<br>
/// *connections*: stores all the connections that are currently open on the interface<br>
/// *terminate*: a flag that is set to true when the interface is dropped<br>
/// *pending*: stores all the connections that are waiting to be accepted on that port
#[derive(Default)]
pub struct ConnectionManager
{
    connections: HashMap<Quad, tcp::Connection>,
    terminate: bool,
    pending: HashMap<u16, VecDeque<Quad>>,
    // VecDeque is a ring buffer -- it's a double ended queue
}

#[derive(Default)]
struct Foobar
{
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,  // this help sin having the condvar within the arc but not within the mutex
    rcv_var: Condvar,
}
type InterfaceHandle = Arc<Foobar>;

pub struct Interface
{
    ih: Option<InterfaceHandle>,        // interface handle -- this is where the stuff for all the connection is .. this is basically the ConnectionManager wrapped in an Arc<Mutex>
    // this is where you're gonna have to lock for READ and WRITE
    jh: Option<thread::JoinHandle<io::Result<()>>>, // join handle for the threads
}

impl Drop for Interface
{
    // this has to tear down the network
    fn drop(&mut self)
    {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;
        drop(self.ih.take());
        self.jh.take().expect("interface dropped more than once").join().unwrap().unwrap();
    }
}


fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()>
{
    // buffer to read the bytes into
    let mut buf = [0u8; 1504];

    loop {

        // we want to read from the nic, but we want to make sure that we'll wake up when the next 
        // timer has to be triggered
        let mut pfd = [nix::poll::PollFd::new(nic.as_raw_fd(), nix::poll::PollFlags::POLLIN)];
        let n = nix::poll::poll(&mut pfd[..], 1).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        // we just made the TimeOut to be at every millisecon dd-- ofc this can be optimized
        assert_ne!(n, -1);
        if n==0
        {
            let mut cmg = ih.manager.lock().unwrap();
            for connection in cmg.connections.values_mut()
            {
                connection.on_tick(&mut nic)?;
            }
        }
        assert_eq!(n, 1);
        // if we get down here, that means the filedescriptor is ready and we can do something with it
        let nbytes = nic.recv(&mut buf[..]).expect("failed to read from Tun");        

        // TODO: if self.terminate && Arc::get_string_refs(ih) == 1 then tear down all connections and return Ok(())

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) 
        {
            Ok(iph) =>
            {
                if iph.version() != 4 {
                    // eprintln!("Ignoring non-IPv4 packet: version={}", iph.version());
                    continue;
                }

                let src = iph.source_addr();    
                let dst = iph.destination_addr();
                let proto = iph.protocol();

                if proto != 0x06 {
                    // eprintln!("BAD PROTOCOL -- Not TCP Packet");
                    // not tcp
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) =>
                    // tcp header
                    {
                        eprintln!("Got TCP Packet: src={:?}, dst={:?}", (src), (dst));
                        // let's get the payload of the TCP packet
                        let datai = iph.slice().len() + tcph.slice().len();   
                        let mut cmg = ih.manager.lock().unwrap();  
                        eprintln!("Set up the MUTEX -- Connection Manager");
                        let cm = &mut *cmg;  // gives a mutable reference to the ConnectionManager as opposed to the MutexGuard
                        let q = Quad 
                        {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };
                        eprintln!("Currently handling ENTRY_QUAD: {:#?}", q);
                        match cm.connections.entry(q)
                        {
                            // * check if there is a connection for the quad
                            // * we already had a connection .. then it's just another packet .. you process it the good old way 
                            // * else ... new packet for different Quad
                            Entry::Occupied(mut c) =>
                            {
                                eprintln!("occupied entry found!");
                                // eprintln!("got packet for known quad: {:#?}", q);
                                // if there is a connection, we're just gonna process the packet
                                let a = c.get_mut()
                                    .on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                                // if we pass in here a packet that we received ,, it's gonna report back whether this particular connection is available for
                                // reading or writing or neither or maybe Both? 

                                eprintln!("Availability: {:?}", a);

                                // TODO: compare before/after -- if it was available for read before this and read after this .. there's no need to notify anyone -- this is more like a performance optimization
                                drop(cmg); // we're gonna give up the lock anyways
                                if a.contains(tcp::Available::READ)
                                {
                                    eprintln!("now available for reading..");
                                    ih.rcv_var.notify_all(); // we gottta notify all the threads on the rcv_var 
                                }
                                if a.contains(tcp::Available::WRITE)
                                {
                                    eprintln!("now available for writing..");
                                    // TODO: ih.snd_var.notify_all();
                                }
                            }
                            // * the connection for the Quad was vacant .. 
                            Entry::Vacant(e) => 
                            {
                                eprintln!("vacant entry found!");
                                // eprintln!("got packet for unknown quad: {:#?}", q);
                                // ? if it's vacant, the question becomes -- is someone waiting for it?
                                // * check if there is a listener waiting on the destination port the given Quad
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port()) 
                                {
                                    // eprintln!("There is a Listener! -- so accepting...");
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )? {
                                        // insert the new Quad into the Connections HashMap
                                        e.insert(c);      
                                        // The Quad is also added to the pending queue for the destination port                              
                                        pending.push_back(q);
                                        // release the lock on the ConnectionManager
                                        drop(cmg);
                                        // notify the other threads waiting for new connections
                                        ih.pending_var.notify_all();
                                        // TODO: wake up pending accept 
                                    }
                                }
                                // else 
                                // {
                                //     eprintln!("No Listener! -- so ignoring...");
                                // }
                            }
                        }
                    }
                    Err(e) => 
                    {
                        eprintln!(
                            "Ignoring weird TCP packet: src={:?}, dst={:?}, error={:?}",
                            (src),
                            (dst),
                            e
                        );
                    }
                }
            }
            Err(e) => 
            {
                eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}

impl Interface
{
    pub fn new() -> io::Result<Self>
    {   
        let nic= tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::new(Foobar::default());

        // now we're gonna spawn some thread .. that's gonna handle the nic
        let jh = 
        {
            let ih = ih.clone();
            thread::spawn(move || {  
                // the thread is gonna run a loop that reads packets from the nic and sends them to the interface
                // anytime it has to touch the connection -- it actually has to take the lock
                packet_loop(nic, ih)

            })
        };
        Ok(Interface { ih: Some(ih), jh: Some(jh) })
    }
    
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener>
    {
        let mut cm = self.ih.as_ref().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port)
        {
            Entry::Vacant(v) =>
            {
                v.insert(VecDeque::new());
            },
            Entry::Occupied(_) =>
            {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "port already in use"));
            }
        };        
        // it has to lock the interface to get the connection manager

        // eprintln!("BOUND: {:#?}", cm.pending);
        
        drop(cm); // releasing the lock
        Ok(TcpListener{
                port, 
                h: self.ih.as_mut().unwrap().clone()
            }) 
        // returns a TcpListener with the port and the interface handle [since it needs to able to lock and accept packets]
    }

}


pub struct TcpListener
{
    port: u16, 
    h: InterfaceHandle
}

impl Drop for TcpListener
{
    fn drop(&mut self)
    {
        // eprintln!("dropped listener!");
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm.pending.remove(&self.port).expect("port closed while listener is active");

        // we also have to close all the connections that are pending -- we have dropped the Listener .. so terminate the connectiosn for it
        for quad in pending
        {
            // TODO: terminate cm.connections[quad]
            unimplemented!();
        }
    }
}

impl TcpListener
{
    pub fn accept(&mut self) -> io::Result<TcpStream>
    {
        let mut cm = self.h.manager.lock().unwrap();
        // new connections are gonna be pushed to the back and popped from the front
        loop {
            if let Some(quad) = cm.pending.get_mut(&self.port).expect("port closed while listener is active").pop_front()
            {
                return Ok(TcpStream{
                            quad, 
                            h: self.h.clone() 
                        });
            }
            cm = self.h.pending_var.wait(cm).unwrap();
        }   
    }
}



pub struct TcpStream
{
    quad: Quad, 
    h: InterfaceHandle
}
// we encapsulate the state of each connection inside the TCP Stream -- this would be very nicer clean separation of concerns

impl Drop for TcpStream
{
    fn drop(&mut self)
    {
        let _cm = self.h.manager.lock().unwrap();
        // TODO: send FIN on connections[quad]
        // TODO: eventually remove self.quads from cm.connections
        // even after we send a FIn , we still gotta wait for them to ACK that FIN .. or else -- we might have to resend the FIN
    }
}
impl Read for TcpStream
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
    {
        // first we gotta get the lock -- since we access to the data that's been read
        let mut cm = self.h.manager.lock().unwrap();

        loop {

                // we look up the connection for the TcpStream that we're trying to read from
            let c = cm.connections.get_mut(&self.quad)
                                    .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;

            
            eprintln!("status: {:#?} {:#?}", c.is_rcv_closed(), c.incoming.is_empty());
            // read the data
            eprintln!("trying to read!");
            if c.is_rcv_closed() && c.incoming.is_empty()
            {
                eprintln!("connection has gone away");
                // if the receiver is closed, and the incoming is empty -- then we just know that we're done reading
                return Ok(0);
                // NO MORE DATA TO READ -- and no need to block because there won't be anymore
            }
            eprintln!("Connection still active!");

            if !c.incoming.is_empty()
            {
                // if we get down here tho -- there is data there -- read however much data we can upto the size of buf
                let mut nread = buf.len();
                //the goal is to copy the data from the incoming slices into our buffer and 
                // then drain the copied data from the incoming connection
                let (head, tail) = c.incoming.as_slices();
                // NOTE: check out as_slices() method
                let hread = std::cmp::min(head.len(), buf.len());
                buf[..hread].copy_from_slice(&head[..hread]);  // we can only copy from contiguous memory so this won't work with ring buffers -- we have to copy separately from the tail too
                nread += hread;
                let tread = std::cmp::min(buf.len()-nread, tail.len());
                // buf.len()-nread might be 0 ..... it might mean that we have read all the data we needed to read
                buf[hread..(hread+tread)].copy_from_slice(&tail[..tread]); // this might read no bytes
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread); // return the number of bytes we end up reading
            }

            

            eprintln!("NOT YET BLOCK");
            // if there's no data -- we have to block
            cm = self.h.rcv_var.wait(cm).unwrap();  // also gotta implement notify and everything in the rcv_var
            
        }

    }
}

impl Write for TcpStream
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>
    {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad)
                                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;

        // so we're trying to write out into c.outgoing buffer
        if c.unacked.len() >= SENDQUEUE_SIZE
        {            
            // TODO: Block
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "too many bytes buffered"));
            // we're gonna have to block until some of the buffered data has been sent into the server
        }

        // instead of reading bytes out .. we're gonna push bytes in

        let nwrite = std::cmp::min(SENDQUEUE_SIZE - c.unacked.len(), buf.len());
        // we're gonna write either as many bytes as we have .. or as many bytes we're allowed to write
        c.unacked.extend(buf[..nwrite].iter().cloned());

        
        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()>
    {
        // block until there are no bytes in the local buffer -- every byte has been acked by the server
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad)
                                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;


        if c.unacked.is_empty()
        {
            Ok(())
        }
        else {
            // TODO: block
            Err(io::Error::new(io::ErrorKind::WouldBlock, "not all bytes have been acked"))
        }
    }
}


impl TcpStream
{
    pub fn shutdown(&self, _how: std::net::Shutdown) -> io::Result<()>
    {
        // first we gotta get a lock for the connection
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad)
                                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated unexpectedly"))?;
        
        c.close();
        Ok(())
    }
}