//extern crate radio_sx127x;


use esp_idf_sys as _; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported
use std::convert::TryInto;
use std::{thread, time::*};
use twoRatchet::ED::{EDRatchet};
use twoRatchet::AS::{ASRatchet};
extern crate alloc;
use alloc::sync::Arc;
use esp_idf_svc as _;
//use embedded_hal::digital::v1::OutputPin;
use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
};
use rand_core::{RngCore,Error,CryptoRng};

use x25519_dalek_ng::{PublicKey,StaticSecret};
use embedded_svc::storage::{Storage};
const SUITE_I: u8 = 3;
const METHOD_TYPE_I : u8 = 0;
const DHR_CONST : u16 = 1;

const ED_STATIC_MATERIAL :[u8;32] = [154, 31, 220, 202, 59, 128, 114, 237, 96, 201, 
18, 178, 29, 143, 85, 133, 70, 32, 155, 41, 124, 
111, 51, 127, 254, 98, 103, 99, 0, 38, 102, 4];

const AS_STATIC_MATERIAL : [u8;32]= [245, 156, 136, 87, 191, 59, 207, 135, 191, 100, 46,
213, 24, 152, 151, 45, 141, 35, 185, 103, 168, 73, 74, 
231, 37, 220, 227, 42, 68, 62, 196, 109];
const DEVEUI : [u8;8] = [0x1,1,2,3,2,4,5,7];
const APPEUI : [u8;8] = [0,1,2,3,4,5,6,7];

fn main() {

    let nvs1 = esp_idf_svc::nvs::EspDefaultNvs::new().unwrap();
    let nvs  = esp_idf_svc::nvs_storage::EspNvsStorage::new_default(Arc::new(nvs1),"nvs",true).unwrap();

    nvs.put_raw("whatever", vec![1,2]);
        /*
    Parti I generate message 1
    */

    let ed_static_priv = StaticSecret::from(ED_STATIC_MATERIAL);
    let ed_static_pub = PublicKey::from(&ed_static_priv);

    


    // AS----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut ed_priv = [0;32];
    HRNG.fill_bytes(&mut ed_priv);



    let i_kid = [0xA2].to_vec();
    let msg1_sender =
        PartyI::new(DEVEUI.to_vec(),APPEUI.to_vec(), ed_priv, ed_static_priv, ed_static_pub, i_kid);


    let (msg1_bytes, msg2_receiver) =

        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();
 
    println!("msg1 {}", msg1_bytes.len());



    /*//////////////////////////////
    /// AS initialize and handle message 1
    *////////////////////////////////////////7

    let as_static_priv = StaticSecret::from(AS_STATIC_MATERIAL);
    let as_static_pub = PublicKey::from(&as_static_priv);


    let as_kid = [0xA3].to_vec();

    // create keying material

    let  as_priv = [0;32];
    HRNG.fill_bytes(&mut ed_priv);

    let msg1_receiver =
       PartyR::new(as_priv, as_static_priv, as_static_pub, as_kid);
       
    let (msg2_sender,deveui,appeui) = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        },
        Ok(val) => val,
    };

    // AS should now validate deveui and appeui
    let (msg2_bytes,msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };

    let devaddr = [2,56,45,12].to_vec();

    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 2, and then generating message 3, and the rck/sck
    ///////////////////////////////////////////////////////////////////// */
    

    // unpacking message, and getting kid, which we in a realworld situation would use to lookup our key
    let  (as_kid ,appeui ,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2_bytes){
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        } 
        Ok(val) => val,
    };


    let msg3_sender = match msg2_verifier.verify_message_2(&as_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
        Ok(val) => val, };

    let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3() {
            Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
            Ok(val) => val,
        };

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */
    
    let (msg3verifier, ed_kid) = match  msg3_receiver.unpack_message_3_return_kid(msg3_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("received error {} in message 3, shutting down", s);
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("sending error {:?}, ",b);
        } 
        Ok(val) => val,
    };

    let (msg4_sender, as_sck, as_rck, as_rk) = match msg3verifier.verify_message_3(&ed_static_pub.as_bytes().to_vec())
    {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("received error {} while verifying message 3, shutting down",s);
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("sending error {:?}, ",b);
        } 
        Ok(val) => val,
    };

        let msg4_bytes =
        match msg4_sender.generate_message_4() {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Received error msg: {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };

    /*///////////////////////////////////////////////////////////////////////////
    /// ED receiving and handling message 4, and generati  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (ed_sck, ed_rck,rk_ed) =
    match msg4_receiver_verifier.handle_message_4(msg4_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    let hrng = HRNG;

    let hrng1 = HRNG;


    let mut ed_ratchet = EDRatchet::new(
        rk_ed.try_into().unwrap(),
        ed_rck.try_into().unwrap(), 
        ed_sck.try_into().unwrap(),
        devaddr.clone(),
        hrng);

    
    let mut as_ratchet = ASRatchet::new(
        as_rk.try_into().unwrap(), 
        as_rck.try_into().unwrap(),
        as_sck.try_into().unwrap(), 
        devaddr.clone(),
        hrng1);



    loop {
        thread::sleep(Duration::from_millis(1000));
        let payload = ed_ratchet.ratchet_encrypt_payload(&[2;3], &devaddr);
        println!("encryprypeed");

        let dh_ack = match  as_ratchet.receive(payload) {
            Some((x,b)) => println!("AS recevied message {:?}", x),
            None => println!("an erorr occurred"), // in this case, do nothing
        };  
        if DHR_CONST <= ed_ratchet.fcnt_up {
            println!("ratch");
            let dhr_req = ed_ratchet.initiate_ratch();
            let dh_ack = match  as_ratchet.receive(dhr_req) {
                Some((x,b)) => x,
                None => continue 
            };
            let _ = ed_ratchet.receive(dh_ack);
        } 

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

struct HRNG;

impl CryptoRng  for HRNG{}
impl RngCore for HRNG {
    fn next_u32(&mut self) -> u32 {
        let mut n : u32 = 0;
        unsafe {
           n = esp_idf_sys::esp_random();
        }
        n
    }

    fn next_u64(&mut self) -> u64 {
        let mut n : u32 = 0;
        unsafe {
           n = esp_idf_sys::esp_random();
        }
        n.try_into().unwrap()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {

        unsafe { 
            esp_idf_sys::esp_fill_random(dest.as_ptr() as *mut core::ffi::c_void, dest.len().try_into().unwrap()); 
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}
