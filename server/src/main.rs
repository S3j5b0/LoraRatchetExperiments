use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write,Error};
use std::io::BufWriter;
use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
    util::{build_error_message}
};
use twoRatchet::ratchfuncs::{state};

use rand::{rngs::StdRng, Rng,SeedableRng};
use x25519_dalek_ng::{PublicKey,StaticSecret};
const LEN : usize = 50;

const R_STATIC_MATERIAL: [u8;32] = [59, 213, 202, 116, 72, 149, 45, 3, 163, 
                                    72, 11, 87, 152, 91, 221, 105, 241, 1, 
                                    101, 158, 72, 69, 125, 110, 61, 244, 236,
                                    138, 41, 140, 127, 132];
const I_STATIC_PK_MATERIAL : [u8;32] =[205, 223, 6, 18, 99, 214, 239, 8, 65, 
                                      191, 174, 86, 128, 244, 122, 17, 32, 242, 
                                      101, 159, 17, 91, 11, 40, 175, 120, 16, 
                                      114, 175, 213, 41, 47];




fn handle_connection(mut stream: TcpStream)-> Result<(), Error>   {

    let r_static_priv = StaticSecret::from(R_STATIC_MATERIAL);
    let r_static_pub = PublicKey::from(&r_static_priv);
    let i_static_pub = PublicKey::from(I_STATIC_PK_MATERIAL);

    println!("incoming connection from: {}", stream.peer_addr()?);

    let mut r : StdRng = StdRng::from_entropy();
    let r_ephemeral_keying = r.gen::<[u8;32]>();
    let r_kid = [0xA3].to_vec();
    let msg1_receiver =
    PartyR::new(r_ephemeral_keying, r_static_priv, r_static_pub, r_kid);
    
    let mut buf = [0;512];
    // read message 1
    let bytes_read = stream.read(&mut buf)?;


    let msg1 = &buf[0..bytes_read];

    // removing mtype and returning error message if mtype is bad
    if msg1[0] != 0 {
        let err = build_error_message("bad mtype");
        stream.write(&err)?;
        return Ok(())

    }
    let msg1 = &msg1[1..];


    let (msg2_sender,appeui,devui) = match msg1_receiver.handle_message_1(msg1.to_vec()) {
        Err(OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b)?;
            return Ok(()) // we really shoulnt fail on the first message
        },
        Ok(val) => {
            val},
    };
    // Generate message
    
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            stream.write(&b)?;// in this case, return this errormessage
            return Ok(())
        } 
        Ok(val) => val,
    };

    /// now generating the Devadd of 4 byues consisting of the NwkID and Devid
    
    let devaddr = [42, 9, 1,6];
        // sending message 2
    
    let mut msg2 = [1].to_vec();
    msg2.extend(devaddr);
    msg2.extend(msg2_bytes);
    
    println!("msg2 {:?}", msg2);
    stream.write(&msg2)?;

        //read message 3

    let mut buf = [0;512];
    // read message 1
    let bytes_read = stream.read(&mut buf)?;
    let msg3 = &buf[0..bytes_read];

    if msg3[0] != 2 {
        println!("receving bad mtype for message 3, closing connection...");
        let err = build_error_message("bad mtype");
        stream.write(&err)?;
        return Ok(())
    }
    let msg3 = msg3[1..].to_vec();

    let tup3 = msg3_receiver.handle_message_3(msg3,&i_static_pub.as_bytes().to_vec());

    let (msg4sender, as_sck,as_rck, as_rk) = match tup3 {
        Ok(v) => v,
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        },
        Err(OwnOrPeerError::OwnError(b)) =>{
            stream.write(&b)?;// in this case, return this errormessage
            return Ok(())
        },
    };

    // send message 4

    let msg4_bytes = // fjern den der len imorgen
    match msg4sender.generate_message_4() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            stream.write(&b)?;// in this case, return this errormessage
            return Ok(())
        }

        Ok(val) => val,
    };

        // sending message 2
        let mut payload4 = [3].to_vec();
        payload4.extend(msg4_bytes);
        stream.write(&payload4)?;
        println!("i_master {:?}", as_rk);
        println!("rck : {:?}", as_rck);
        println!("sck : {:?}", as_sck);
 
        let mut r_ratchet = state::init_r(as_rk.try_into().unwrap(), 
                                         as_rck.try_into().unwrap(),
                                         as_sck.try_into().unwrap(), 
                                         devaddr.to_vec());

    let mut n = 0;
        loop {
            println!("start reading input");
            let mut buf = [0;64];
            stream.read_exact(&mut buf)?;
            let incoming = &buf;
            println!("getting {:?}", incoming);
            
              let (newout,sendnew) = match  r_ratchet.r_receive(&incoming.to_vec()) {
                Some((x,b)) => (x,b),
                None => { 
                    println!("error has happened {:?}", incoming);
                    continue
                }, 
            };
          if !sendnew {
            } else {
                println!("seinding {:?}", newout);
                match stream.write(&newout) {
                    Ok(_) => println!("ok"),
                    Err(x)=> println!("err {:?}", x),
                }
               
            }
            n += 1;
            println!("n {}", n);
            
        }



        
        return Ok(())
    
}

fn main() {

    // static key material of r (stored in efuse)


    let listener = TcpListener::bind("192.168.1.227:8888").unwrap();


    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
