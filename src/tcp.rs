// 1) A --> B  SYN my sequence number is X
// 2) A <-- B  ACK your sequence number is X
// 3) A <-- B  SYN my sequence number is Y
// 4) A --> B  ACK your sequence number is Y

use std::{collections::VecDeque, io, time, collections::BTreeMap};   
use std::io::Write;

use bitflags::bitflags;
// for sturcts that manage a set of flags
bitflags! 
{
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct Available: u8
    {
        const READ  = 0b00000001;
        const WRITE = 0b00000010;
    }
}

/// stores the TCP States as defined in [RFC 793](https://tools.ietf.org/html/rfc793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State
{
    SynRcvd,
    Estab,
    FinWait1,  // we have sent a FIN and it has not yet been acked 
    FinWait2,    
    TimeWait,
}

impl State
{
    /// helper method to check if the connection is fully synchronized
    fn is_synchronized(&self) -> bool
    {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,   // since the connection is established now .. so it is fully synchronized now -- they can now start exchanging data
            State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
    // we also need a mechanism to determine whether we have or not sent the FIN
}

/// Transmission Control Block -- this is..sort of the state that has to be kept for every connection
pub struct Connection
{
    pub state: State,
    /// we update this when sending a packet
    send: SendSequenceSpace,  
    /// we update this when we receive a packet .. each side maintains it's own set of sequence spaces
    recv: RecvSequenceSpace,  
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,
    pub(crate) incoming: VecDeque<u8>,
    /// bytes that the user has given us, but we haven't been able to send yet
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) closed: bool,  // this is the FIN byte -- virtual byte at the end of the send stream 
    closed_at: Option<u32>,  // this is keep track of the sequence number we have used for the FIN if we have sent it
}

pub struct Timers
{
    send_times: BTreeMap<u32, time::Instant>, // (sequence number, when that was sent
    srtt: f64,
}

/*
Send Sequence Variables:  [check it out from the rfc]

    SND.UNA - send unacknowledged -- the sequence number of the first byte of data that has not been acknowledged by the other end
    SND.NXT - send next -- the sequence number of the next byte of data that the sender will send
    SND.WND - send window -- the size of the send window --- the receiver can only accept this much data
    SND.WL1 - used for updating the windows
    SND.WL2 - used for updating the windows
    ISS     - Initial Sequence Number  -- what we choose when we started the connection

Recieve Sequence Variables:

    RCV.NXT - receive next
    RCV.WND - receive window
    RCV.UP  - receive urgent pointer
    IRS     - initial receive sequence number

Also go through Sequence Numbers in Sec. 3.3 of [RFC 793]
*/

/// ```
/// Send Sequence Space

///                    1         2          3          4      
///               ----------|----------|----------|---------- 
///                      SND.UNA    SND.NXT    SND.UNA        
///                                           +SND.WND        

///         1 - old sequence numbers which have been acknowledged  
///         2 - sequence numbers of unacknowledged data            
///         3 - sequence numbers allowed for new data transmission 
///         4 - future sequence numbers which are not yet allowed  
/// ```
struct SendSequenceSpace {
    /// first byte of data that has been sent but not yet been acknowledged by the other side
    una: u32, 
    /// next sequence number to be sent
    nxt: u32, 
    /// send window size
    wnd: u16,
    /// urgent pointer 
    up: bool,
    /// used for updating the windows
    wl1: usize,
    /// used for updating the acknowledgment number
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// ```
/// Receive Sequence Space

///           1          2          3      
///      ----------|----------|---------- 
///              RCV.NXT    RCV.NXT        
///                        +RCV.WND        

/// 1 - old sequence numbers which have been acknowledged  
/// 2 - sequence numbers allowed for new reception         
/// 3 - future sequence numbers which are not yet allowed  
/// ```
struct RecvSequenceSpace {
    nxt: u32,
    wnd: u16,
    up: bool,
    irs: u32,
}

impl Connection 
{
    pub(crate) fn is_rcv_closed(&self) -> bool
    {
        eprintln!("Asked if closed when in {:#?}", self.state);
        if let State::TimeWait = self.state
        {
            // TODO: any state after received FIN, also CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        }
        else
        {
            false
        }
    }

    pub(crate) fn availability(&self) -> Available
    {
        let mut a = Available::empty();
        eprintln!("Computing Availability");
        if self.is_rcv_closed() || !self.incoming.is_empty()
        {
            a |= Available::READ;
        }
        // TODO: take into account self.state     ---- it might only have to be taken into account for Write
        // TODO: set Available::Write
        return a;
    }

    
    pub(crate) fn accept<'a>(  // accept a new connection   -- assumes you have no current state -- this is going to produce a state
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>, 
        tcph: etherparse::TcpHeaderSlice<'a>, 
        data: &'a [u8],   // this is the body of the TCP packet -- data that the other side wants to send us
    )    -> io::Result<Option<Self>>
    {
        let buf = [0u8; 1500];
        
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        // let mut buf = [0u8; 1500];
        let iss = 0;  // initial sequence number
        let wnd = 1024;
        let mut c = Connection 
        {
            timers: Timers{                
                send_times: Default::default(),
                srtt: time::Duration::from_secs(60).as_secs_f64(),
            },
            closed: false,
            closed_at: None,
            state: State::SynRcvd,
            send: SendSequenceSpace {
                //decide the stuff we're sending them -- establish our send sequence space
                iss: iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
                up: false,
                wl1: 0,  // how aggressive we should be about sending things
                wl2: 0,  // how aggressive we should be about sending things
            },
            recv: RecvSequenceSpace {
                // keep track of sender info
                irs: tcph.sequence_number(),  // sequence number that they just sent us
                nxt: tcph.sequence_number() + 1, // next byte we're expecting them to send
                wnd: tcph.window_size(),  // amount of data we're are willing to accept                
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64, // time to live
                etherparse::IpTrafficClass::Tcp, 
                [
                    iph.destination()[0],
                    iph.destination()[1], 
                    iph.destination()[2],
                    iph.destination()[3], 
                ],  
                [
                    iph.source()[0], 
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
                // keep in mind that we're working on the connection here .. server side if you will .. so the source of the SYN packet is the destination of the SYN_ACK packet
            ),
            tcp: etherparse::TcpHeader::new(              // we got a SYN .. we gotta store that and start with the checks to establish a connection
                tcph.destination_port(),
                tcph.source_port(),
                iss,
                wnd,
            ),
            incoming:  Default::default(),
            unacked: Default::default(),
        };        
                
        // if we got a SYN -- we need to start establishing a connection
        // we gotta parse out the SYN packet and send a SYN-ACK
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, c.send.nxt, 0)?;  // you pass the default initial sequence number 
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize>
    {        
        // we never past the end of the input stream
        // We will write to an inmemory buffer that will later write to the actual output
        let mut buf = [0u8; 1500];
        // self.tcp.sequence_number = self.send.nxt;
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // TODO: return +1 for SYN/FIN
        eprintln!(
            "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
            self.recv.nxt - self.recv.irs, seq, limit, self.tcp.syn, self.tcp.fin,
        );

        let mut offset = seq.wrapping_sub(self.send.una) as usize; 
        // position within the unacked buffer data from where you need to start writing the data
        
        // we need to special case the 2 virtual bytes --- the SYN and FIN
        if let Some(closed_at) = self.closed_at
        {
            if seq == closed_at.wrapping_add(1)
            {
                // if we're asked to send bytes after the FIN .. then we need to set the offset to 0.. where we should not be reading any data 
                offset = 0;
                // trying to write following FIN
                limit = 0;
            }
        }

        eprintln!("Using offset: {} base: {} in {:?}", offset, self.send.una, self.unacked.as_slices());

        let (mut h, mut t) = self.unacked.as_slices();
        // we want self.unacked[nunacked..]
        if h.len() >= offset
        {
            h = &h[offset..];
        }
        else
        {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());

        let size = std::cmp::min(buf.len(), self.ip.header_len() as usize + self.tcp.header_len() as usize +  max_data);

        self.ip.set_payload_len(size - self.ip.header_len() as usize);

        // Write out headers =========>  IP Header + TCP Header    

        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];
        
        self.ip.write(&mut unwritten);
        let ip_header_ends_at = buf_len - unwritten.len();

        // we need the entire payload as one contiguous slice to calculate the checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        // here comes the payload
        let payload_bytes = {
            
            let mut written = 0;
            let mut limit = max_data;

            // first write as much as we can from h
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written; // decrease the limit by however much we from payload1

            // write more if we can from t
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..p2l])?;

            written // we wrote this many bytes from the 2 payloads
        };  

        let payload_ends_at = buf_len - unwritten.len();

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.write(&mut tcp_header_buf);
        
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn
        {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin
        {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq)
        {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_ends_at])?;

        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()>
    {
        // TODO: fix sequence numbers here 
        /*
        If the incoming connection has an ACK field, the reset takes its sequence number from the ACK field of the segment, 
        otherwise the reset has sequence number zero and the ACK field is set to the sum of the sequence number and segment length of the incoming segment.

        The connection remains in the same state.
         */
        // TODO: handle synchronized reset
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;        
        self.write(nic, self.send.nxt,  0)?;
        Ok(())
    }

    pub(crate) fn on_tick<'a>(  // we receive a packet and we have some current state
        &mut self,
        nic: &mut tun_tap::Iface,
    ) -> io::Result<()>
    {
        // decide if it needs to send something
        // if we're allowed to send stuff then we send it .. 
        // if we're not allowed to send stuff then we need to check for stuff that needs to be retransmitted
        // if FIN, enter FIN-WAIT-1

        let nunacked = self.send.nxt.wrapping_sub(self.send.una) as usize; // number of bytes sent by unACKed
        let unsent = self.unacked.len() - nunacked as usize; // number of bytes that we have not sent yet

        // read the RFC .. 2 min is recommended for retransmissions when the window is 0 --- set in the accept function
        // When the TCp transmits something it puts in the retransmission queue with a timer ...
        // if an ack is received before the timer runs out .. then remove data from the retransmission queue ... else retransmit


        // how long is it since the last thing we sent that is unacked -- if the time that has expired there is more than the timeout then retransmit
        let waited_for = self.timers.send_times.range(self.send.una..).next().map(|t| t.1.elapsed());

        let should_retransmit = 
        if let Some(waited_for) = waited_for 
        {
            waited_for > time::Duration::from_secs(1) && waited_for.as_secs_f64() > self.timers.srtt * 1.5
        }
        else
        {
            // if there is no running retransmission timers then ofc we shouldn't retransmit -- since there wouldn't be anything to resend
            false
        };

        eprintln!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
                  self.state, self.send.una, self.send.nxt, self.unacked);

        if should_retransmit
        {
            // we should retransmit things
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed
            {                
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            self.write(nic, self.send.una,  resend as usize)?;
        }
        else 
        {
            // we should send new data if we have it and some space in the window
            if unsent == 0 && self.closed_at.is_some()
            {
                return Ok(()); // we have no more data to send -- the connection is closed and we have sent the FIN
            }
            // otherwise we should just send out as many bytes we're allowed to send
            let allowed = self.send.wnd as u32 - nunacked as u32;
            if allowed == 0
            {
                return Ok(()); // we can't send any data -- we also aren't supposed to retransmit anything
            }
            
            let send = std::cmp::min(unsent, allowed as usize);
            if send < allowed as usize && self.closed && self.closed_at.is_none()
            { // we're allowed to send more, we are supposed to send the FIN, and we have not yet sent the FIN
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));  // unacked start + num_unacked --> FIN
            }            

            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(())
    } 

    pub(crate) fn on_packet<'a>
    (  // we receive a packet and we have some current state
        &mut self,
        nic: &mut tun_tap::Iface,             // mutable reference to the tun-tap interface
        _iph: etherparse::Ipv4HeaderSlice<'a>, // parsed ip header of the incoming connection
        tcph: etherparse::TcpHeaderSlice<'a>, // parsed tcp header of the incoming connection
        data: &'a[u8],                        // reference to the payload of the incoming connection
    )    -> io::Result<Available>
    {
        // first, check that segments are valid (RFC 793 S3.3)  ---- 
        //  check if even the packet is valid so that we can accept it
        let seqn = tcph.sequence_number();                           // this is SEG.SEQ
        let mut slen = data.len()  as u32;                           // SEG.LEN
        
        // for acceptable ack check:
        // SND.UNA < SEG.ACK =< SND.NXT
        // let ackn = tcph.acknowledgment_number();                    // SEG.ACK

        if tcph.fin()
        {
            // if the packet has a FIN flag set, then we need to increment the segment length -- why? because the FIN flag is also a byte
            // to account for the additional byte ... 
            // when the sender sends a FIN ... it consumes an extra sequence number of the packet ... 
            // we're working on the packet the sender sent .. don't whine about it ..
            slen += 1;
        };

        if tcph.syn()
        {
            // if the packet has a SYN flag set, then we need to increment the segment length
            // it indicates the synchronization of the sequence numbers
            slen += 1;
        };
        
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32); // end of the receiver's window: RCV.NXT + RCV.WND    

        let okay =
            if slen == 0
            {
                // zero length segment has its own rules: [we're talking about the received segment here]

                // Length  Window
                // ------- -------  -------------------------------------------
            
                //    0       0     SEG.SEQ = RCV.NXT            
                //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND            
                //   >0       0     not acceptable            
                //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            
                if self.recv.wnd == 0 // receiver is not ready for any data
                {
                    if seqn != self.recv.nxt
                    {
                        false
                    }
                    else 
                    {
                        true
                    }
                }
                else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) 
                // receiver is ready to receive data
                {
                    false
                } 
                else 
                {
                    true
                }
            }
            else // NON-ZERO LENGTH SEGMENT
            {
                if self.recv.wnd == 0
                {
                    false // receiver is not ready for any data
                }

                else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1) ,seqn,  wend)
                        && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn.wrapping_add(slen -1) , wend)
                {
                    // The first byte (SEG.SEQ) falls within the valid range:
                    // RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND

                    // The last byte (SEG.SEQ + SEG.LEN - 1) falls within the valid range:
                    // RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND
                    false
                }
                else 
                {
                    true
                }
            };
            
        if !okay
        {
            eprintln!("NOT OKAY!");
            self.write(nic, self.send.nxt,   0)?;
            return Ok(self.availability());
        }

        // TODO: if_not_acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>        
        
        if !tcph.ack()
        {
            if tcph.syn()
            {
                // got SYN part of initial handshake
                assert!(data.is_empty()); // since it's the first packet, we don't expect any data -- you can't send bytes in the first packet of the handshake
                self.recv.nxt = seqn.wrapping_add(1);
            }
            eprintln!("NO ACK!!");
            return Ok(self.availability());
        }
        
        let ackn = tcph.acknowledgment_number();

        if let State::SynRcvd = self.state 
        {
            // check if ackn is within a valid range
            if !is_between_wrapped(self.send.una.wrapping_sub(1), ackn, self.send.nxt.wrapping_add(1))
            {

                self.state = State::Estab;
            }
            else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) 
            {
                eprintln!(" ack for {} (last: {}) prune in {:?} ", 
                            ackn, self.send.una, self.unacked);
                if !self.unacked.is_empty()
                {
                    let data_start = if self.send.una == self.send.iss
                    {
                        // data starts just after UNA
                        self.send.una.wrapping_add(1)
                    }
                    else
                    {
                        self.send.una
                    };

                    let acked_data_end = std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    // we also wanna remove any of the timers that are relevant
                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let srtt = &mut self.timers.srtt;

                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                                if is_between_wrapped(una, seq, ackn)
                                {
                                    // if the sequence number of the timer is in the list that has now been acked -- then remove it .. since it's no longer relevant
                                    // also gotta deal with the SRTT
                                    
                                    *srtt = 0.8 * (*srtt) + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                    None // we're gonna remove the timer
                                }
                                else {
                                    Some((seq, sent))
                                }
                            }
                        )
                    );
                }
                
                self.send.una = ackn;
            }

            // TODO: if unacked and waiting flush, then notify the user that the flush is completed
            // TODO: Update the current window size

        }

        // valid sequence check. Okay if it acks atleast one byte, which means that at least one of 
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ           < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        // the reason for including both these checks if for including the first byte of the segment and the last byte of the segment
        

        //                   ::::Basic 3 - way handshake::::                                [RFC 793 S3.4]
        //
        //   TCP A                                                      TCP B  
        //   1.  CLOSED                                               LISTEN
        //   2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED
        //   3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED    // sends an ACK to the SYN received and also sends a 
        //   4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
        //   5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED

        if let State::FinWait1 = self.state 
        {
            if let Some(closed_at) = self.closed_at 
            {
                if self.send.una == closed_at.wrapping_add(1) 
                {
                    // our FIN was ACKed!
                    self.state = State::FinWait2;
                }
            }           
        }        

        if !data.is_empty()
        {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state
            {
                let mut unread_data_at = (self.recv.nxt - seqn) as usize;
                if unread_data_at > data.len()
                {
                    // We must have received a retransmitted FIN that we have already seen
                    // nxt points to beyond the FIN -- but the FIN is not in data
                    assert_eq!(unread_data_at, data.len()+1);
                    unread_data_at = 0;
                }
                eprintln!(" reading data at ({} : {}) from {:#?}", self.recv.nxt, seqn, data);

                // when we receive data we need to stick it into incoming buffer                
                self.incoming.extend(&data[unread_data_at..]); // add the data to the incoming buffer   -- this is no longer empty
                // the readers are woken by the main event loop based on what the function returns 
                // we also need to ack the bytes that we received to the other side

                self.recv.nxt = seqn.wrapping_add(data.len() as u32); // we update self.recv.nxt here

                /*
                * Once the TCP takes accountability for the data it receives,
                * it advances RCV.NXT over the data accepted and adjusts the RCV.WND
                * as appropriate to the current buffer availability.
                * The total of RCV.NXT and RCV.WND should not be reduced.

                * SEND_ACK ===> Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                */

                self.write(nic, self.send.nxt, 0)?; // this will send the acknowledgement to the other side

            } 
        }      


        if tcph.fin()
        {
            // since a FIN has been received .... now we know that there's no more data
            match self.state 
            {
                State::FinWait2 =>
                {
                    // So here is where we get a FIN from the other side
                    // we're done with the connection
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                    eprintln!("they've finned!");
                },
                _ => unimplemented!(),
            }
        }


        Ok(self.availability())

    }

    pub(crate) fn close(&mut self) -> io::Result<()>
    {
        self.closed = true;
        match self.state
        {
            State::SynRcvd | State::Estab =>
            {
                self.state = State::FinWait1;                
            }
            State::FinWait1 | State::FinWait2 =>
            {
                // do nothing
            }
            _ =>
            {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "already closing"));
            }
        };
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool 
{
    // From RFC1323:
        // TCP determines if a data segment is "old" or "new" by testing
        // whether its sequence number is within 2**31 bytes of the left edge
        // of the window, and if it is not, discarding the data as "old".
        // To insure that new data is never mistakenly considered as old and vice-versa,
        // the left edge of the sender's window has to be at most 
        // 2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool
{
    wrapping_lt(start, x) && wrapping_lt(x, end)
}