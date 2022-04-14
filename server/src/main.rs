use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write,Error};
use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyR,
    util::{build_error_message}
};
use twoRatchet::AS::{ASRatchet};

use rand::{rngs::StdRng, Rng,SeedableRng};
use rand_core::{OsRng};
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

    let mut ratchet = ASRatchet::new(as_rk.try_into().unwrap(), 
                                         as_rck.try_into().unwrap(),
                                         as_sck.try_into().unwrap(), 
                                         devaddr.to_vec(),
                                        OsRng);

    let mut n = 0;
        loop {
            let mut buf = [0;64];
            stream.read_exact(&mut buf)?;
            let incoming = &buf;
            println!("getting {:?}", incoming);
              let (newout,sendnew) = match  ratchet.receive(incoming.to_vec()) {
                Ok((x,b)) => (x,b),
                Err(e) => { 
                    println!("error has happened {:?}", incoming);
                    continue
                }, 
            };
            
          if !sendnew {
            } else {
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

    // The AS first creates keys, and generates initial state for receiving message 1
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


    let phypayload0 = &buf[0..bytes_read];

    // Checking mtype before unpacking
    if phypayload0[0] != 0 {
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("stream writing error");
        return None

    }
    let msg1 = unpack_edhoc_first_message(phypayload0);

    // Sending message 2
    let mut fcnt_down = 0;
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
    // Generate message 2
     
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} generating message 2, shutting down", s);
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
    
    
    let mut rng : StdRng = StdRng::from_entropy();
    let devaddr = rng.gen::<[u8;4]>();
    // sending message 2, as phypayload 1
    
    let phypayload1 = prepare_edhoc_message(1, fcnt_down, Some(devaddr), msg2_bytes);
    fcnt_down += 1;
    
    stream.write(&phypayload1).expect("stream writing error");

    //unpack message 3, and verify it


    let mut buf = [0;128];
    // read message 1
    let bytes_read = stream.read(&mut buf).expect("stream reading error");
    let phypayload2 = &buf[0..bytes_read];

    if phypayload2[0] != 2 {
        println!("receving bad mtype for message 3, closing connection...");
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("stream writing error");
        return None
    }

    let msg3 = extract_edhoc_message(phypayload2)?;

    let (msg3verifier, kid) = match  msg3_receiver.unpack_message_3_return_kid(msg3.edhoc_msg) {
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
    // now that the kid of the ed has been retrieved, it's public key can be found

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
    let phypayload3 = prepare_edhoc_message(3, fcnt_down, Some(devaddr), msg4_bytes);
    stream.write(&phypayload3).expect("stream writing error");
    return Some((as_sck, as_rck, as_rk, devaddr.to_vec()))

}


struct EdhocMessage {
    m_type: u8,
    fcntup: [u8; 2],
    devaddr: [u8; 4],
    edhoc_msg: Vec<u8>,
}

fn prepare_edhoc_message(mtype : u8, fcnt : u16,devaddr : Option<[u8;4]>, edhoc_msg:Vec<u8> ) -> Vec<u8> {
    let mut buffer : Vec<u8> = Vec::with_capacity(7+edhoc_msg.len());
    buffer.extend_from_slice(&[mtype]);
    buffer.extend_from_slice(&fcnt.to_be_bytes());
    if devaddr != None {
        buffer.extend_from_slice(&devaddr.unwrap())
    };
    buffer.extend_from_slice(&edhoc_msg);

    buffer
}
fn extract_edhoc_message(msg: &[u8]) -> Option<EdhocMessage> {
    let m_type = msg[0];
    let fcntup = msg[1..3].try_into().ok()?;
    let devaddr = msg[3..7].try_into().ok()?;
    let edhoc_msg = msg[7..].try_into().ok()?;
    Some(EdhocMessage {
      m_type,
      fcntup,
      devaddr,
      edhoc_msg
    })
  }
fn unpack_edhoc_first_message(msg: &[u8]) -> Vec<u8> {
    let msg = &msg[1..]; // fjerne mtype
    let _framecounter = &msg[0..2]; // gemme framecounter
    let msg = &msg[2..]; // fjerne frame counter
    msg.to_vec()
}
