use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write,Error,ErrorKind};
use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyR,
    util::{build_error_message}
};
use twoRatchet::AS::{ASRatchet};

use rand::{rngs::StdRng, Rng,SeedableRng};
use x25519_dalek_ng::{PublicKey,StaticSecret};

const R_STATIC_MATERIAL: [u8;32] = [59, 213, 202, 116, 72, 149, 45, 3, 163, 
                                    72, 11, 87, 152, 91, 221, 105, 241, 1, 
                                    101, 158, 72, 69, 125, 110, 61, 244, 236,
                                    138, 41, 140, 127, 132];
const I_STATIC_PK_MATERIAL : [u8;32] =[205, 223, 6, 18, 99, 214, 239, 8, 65, 
                                      191, 174, 86, 128, 244, 122, 17, 32, 242, 
                                      101, 159, 17, 91, 11, 40, 175, 120, 16, 
                                      114, 175, 213, 41, 47];


const DEVEUI : [u8;8] = [0x1,1,2,3,2,4,5,7];
const APPEUI : [u8;8] = [0,1,2,3,4,5,6,7];



fn main() -> Result<(),Error> {



    let listener = TcpListener::bind("192.168.1.227:8888").unwrap();


    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        handle_connection(&mut stream)?;
    }

    Ok(())
}


fn handle_connection(stream: &mut TcpStream)-> Result<(), Error>   {

    println!("incoming connection from: {}", stream.peer_addr()?);

    // Running EDHOC join procedure
    let (as_sck, as_rck, as_rk,devaddr) =  match join_procedure(stream) {
        Some(join_output) => join_output,
        None => return Ok(())
    };

    let mut r_ratchet = ASRatchet::new(as_rk.try_into().unwrap(), 
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
              let (newout,sendnew) = match  r_ratchet.receive(incoming.to_vec()) {
                Some((x,b)) => (x,b),
                None => { 
                    println!("error has happened {:?}", incoming);
                    continue
                }, 
            };
            
          if !sendnew {
            println!("decrypted payload {:?}", newout);
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



        
    
}


fn join_procedure( stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>,Vec<u8>,Vec<u8>)>{
    let as_static_priv = StaticSecret::from(R_STATIC_MATERIAL);
    let as_static_pub = PublicKey::from(&as_static_priv);
    

    

    let mut rng : StdRng = StdRng::from_entropy();
    let as_ephemeral_keying = rng.gen::<[u8;32]>();

    let as_kid = [0xA3].to_vec();
    let msg1_receiver =
    PartyR::new(as_ephemeral_keying, as_static_priv, as_static_pub, as_kid);
    
    let mut buf = [0;128];
    // read message 1
    let bytes_read = stream.read(&mut buf).expect("stream reading error");


    let msg1 = &buf[0..bytes_read];

    // removing mtype and returning error message if mtype is bad
    if msg1[0] != 0 {
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("stream writing error");
        return None

    }


    let msg1 = &msg1[1..];


    let (msg2_sender,deveui,appeui) = match msg1_receiver.handle_message_1(msg1.to_vec()) {
        Err(OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b).expect("stream writing error");
            return None
        },
        Ok(val) => {
            val},
    };

    // this is simply an indication that the AS should check the appeui and devui
    assert_eq!(APPEUI.to_vec(), appeui);
    assert_eq!(DEVEUI.to_vec(), deveui);
    // Generate message
    
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} in message 2, shutting down", s);
            return None
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b).expect("stream writing error");
            return None
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
    stream.write(&msg2).expect("stream writing error");

        //read message 3

    let mut buf = [0;128];
    // read message 1
    let bytes_read = stream.read(&mut buf).expect("stream reading error");
    let msg3 = &buf[0..bytes_read];

    if msg3[0] != 2 {
        println!("receving bad mtype for message 3, closing connection...");
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("stream writing error");
        return None
    }
    let msg3 = msg3[1..].to_vec();

    let (msg3verifier, ed_kid) = match  msg3_receiver.unpack_message_3_return_kid(msg3) {
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} in message 3, shutting down", s);
            return None;
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b).expect("stream writing error");
            return None
        } 
        Ok(val) => val,
    };

    let ed_static_pub = PublicKey::from(I_STATIC_PK_MATERIAL);

    let (msg4_sender, as_sck, as_rck, as_rk) = match msg3verifier.verify_message_3(&ed_static_pub.as_bytes().to_vec())
    {
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} while verifying message 3, shutting down",s);
            return None
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b).expect("stream writing error");
            return None
        } 
        Ok(val) => val,
    };
    // send message 4

    let msg4_bytes = 
    match msg4_sender.generate_message_4() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            println!("sending error {:?}, ",b);
            stream.write(&b).expect("stream writing error");// in this case, return this errormessage
            return None
        }

        Ok(val) => val,
    };
            // sending message 2
    let mut payload4 = [3].to_vec();
    payload4.extend(msg4_bytes);
    stream.write(&payload4).expect("stream writing error");
    return Some((as_sck, as_rck, as_rk, devaddr.to_vec()))

}



fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
