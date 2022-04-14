


extern crate  alloc;

use std::io::{Read, Write};
use std::net::{ TcpStream};
use std::{env,  sync::Arc, thread};
use std::time::Duration;

use core::convert::TryInto;

use embedded_svc::httpd::*;
use embedded_svc::ipv4;
use embedded_svc::ping::Ping;

use embedded_svc::wifi::*;


use esp_idf_svc::netif::*;
use esp_idf_svc::nvs::*;
use esp_idf_svc::ping;
use esp_idf_svc::sysloop::*;

use esp_idf_svc::wifi::*;
use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI,
    util::{build_error_message}
};

use twoRatchet::ED::{EDRatchet};

use rand::{rngs::StdRng, Rng,SeedableRng};

use rand_core::{OsRng};
use x25519_dalek_ng::{PublicKey,StaticSecret};


const SUITE_I: u8 = 3;
const METHOD_TYPE_I : u8 = 0;
const DHR_CONST : u16 = 256;

const I_STATIC_MATERIAL :[u8;32] = [154, 31, 220, 202, 59, 128, 114, 237, 96, 201, 
18, 178, 29, 143, 85, 133, 70, 32, 155, 41, 124, 
111, 51, 127, 254, 98, 103, 99, 0, 38, 102, 4];

const R_STATIC_PK : [u8;32]= [245, 156, 136, 87, 191, 59, 207, 135, 191, 100, 46,
213, 24, 152, 151, 45, 141, 35, 185, 103, 168, 73, 74, 
231, 37, 220, 227, 42, 68, 62, 196, 109];


const DEVEUI : [u8;8] = [0x1,1,2,3,2,4,5,7];
const APPEUI : [u8;8] = [0,1,2,3,4,5,6,7];


const ED_KID : [u8;1]=  [0xA2];



#[cfg(not(feature = "qemu"))]
const SSID: &str = env!("RUST_ESP32_STD_DEMO_WIFI_SSID");
#[cfg(not(feature = "qemu"))]
const PASS: &str = env!("RUST_ESP32_STD_DEMO_WIFI_PASS");




fn main() -> Result<()> {


    // initialize wifi stack
    esp_idf_sys::link_patches();
    #[allow(unused)]
    let netif_stack = Arc::new(EspNetifStack::new()?);
    #[allow(unused)]
    let sys_loop_stack = Arc::new(EspSysLoopStack::new()?);
    #[allow(unused)]
    let default_nvs = Arc::new(EspDefaultNvs::new()?);
    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut wifi = wifi(
        netif_stack.clone(),
        sys_loop_stack.clone(),
        default_nvs.clone(),
    )?;


   match TcpStream::connect("192.168.1.227:8888") {
        Ok(mut stream) => {
        handle_connection(&mut stream)
        }
        Err(e) => {
            panic!("Could not connect to server {}", e);
        }
    }?;


    Ok(())
}


fn handle_connection(stream: &mut TcpStream)-> Result<(), Error>   {

    // perform join procedure
    let (ed_sck, ed_rck, ed_rk,devaddr) =  match join_procedure(stream) {
        Some(join_output) => join_output,
        None => return Ok(())
    };
    // initialize ratchet
    let  mut ratchet = EDRatchet::new(ed_rk.try_into().unwrap(),ed_rck.try_into().unwrap(), ed_sck.try_into().unwrap(),devaddr.to_vec(),OsRng);
    

    // running continous communications, with a 1 second thread sleep 
    // For every iteration, a uplink message is sent, and the 
    stream.set_read_timeout(Some(Duration::from_millis(5000))).expect("Could not set a read timeout");
    loop {
        thread::sleep(Duration::from_millis(1000));
        let uplink = ratchet.ratchet_encrypt_payload(&[1;34], &devaddr);
        stream.write_all(&uplink)?;
        stream.flush()?;
        

        if ratchet.fcnt_up >= DHR_CONST{
            let dhr_req = ratchet.initiate_ratch();
            stream.write_all(&dhr_req)?;
            stream.flush()?;
            let mut buf = [0;64];
            let bytes_read = match stream.read(&mut buf){
                Ok(bytes) => {bytes},
                _ => continue,
            };
            let dhr_ack = &buf[0..bytes_read];
            match ratchet.receive(dhr_ack.to_vec()) {
                Ok(x) => match x {
                    Some(x) => println!("receiving message from server {:?}", x),
                    None => continue
                }
                Err(s) => {
                println!("error during receive {}",s);
                continue}
            };
        }  
        else {
            // if we do not want to send a DHReq, then we'll just listen for a message
            let mut buf = [0;64];
            let bytes_read = match stream.read(&mut buf) {
                Ok(bytes) => bytes,
                _ => continue,
            };
            let downlink = &buf[0..bytes_read]; // if this is not the dhrack, it will still be decrypted and handled
            match ratchet.receive(downlink.to_vec()) {
                Ok(x) => match x {
                    Some(x) => println!("receiving message from server {:?}", x),
                    None => continue
                }
                Err(s) => {
                println!("error during receive {}",s);
                continue}
            };
        }
    }


}

fn join_procedure( stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>,Vec<u8>,Vec<u8>)>{
    // The ED first creates keys, and generates initial state for sending
    let ed_static_priv = StaticSecret::from(I_STATIC_MATERIAL);
    let ed_static_pub = PublicKey::from(&ed_static_priv);

   
    let mut r : StdRng = StdRng::from_entropy();
    let ed_ephemeral_keying = r.gen::<[u8;32]>();

    let msg1_sender =
        PartyI::new(DEVEUI.to_vec(), APPEUI.to_vec(), ed_ephemeral_keying, ed_static_priv, ed_static_pub, ED_KID.to_vec());

    let (msg1_bytes, msg2_receiver) =
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();

    let mut fcnt_up = 0;

    // The ED then prepares the first message into a appropriate phypayload, and send it

    let mut phypayload0 = prepare_edhoc_message(0, fcnt_up, None, msg1_bytes);
    fcnt_up += 1;
    stream.write(&phypayload0).expect("error during write");

    // The second message is now received from the AS, checked for mtype, and the phypayload fields are extracted
    let mut buf = [0;128];
    let bytes_read = stream.read(&mut buf).expect("error during read");
    let phypayload1 = &buf[0..bytes_read];

    if phypayload1[0] != 1 {
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("error during write");
        return None
    }
    let msg2 = extract_edhoc_message(phypayload1)?;
    let devaddr= msg2.devaddr;

    // The ED extracts the kid from message 2
    
    let  (kid, appeui,msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2.edhoc_msg){
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} in message 2, shutting down", s);
            return None
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            stream.write(&b).expect("error during write");// in this case, return this errormessage
            return None
        } 
        Ok(val) => val,
    }; 

    if APPEUI.to_vec() != appeui {
        return None
    }
    
    
    // With the kid, the ED can now retrieve the public static key and verify message 2
    let as_static_pub = PublicKey::from(R_STATIC_PK);
    let msg3_sender = 
        match msg2_verifier.verify_message_2(as_static_pub.as_bytes()) {
            Err(OwnError(b)) => {
                stream.write(&b).expect("error during write");
                return None},
            Ok(val) => val, };


    
    // now that the fields of message 2 has been fully verified, the ED can generate message 3
    
    let (msg4_receiver_verifier, msg3_bytes) =
        match msg3_sender.generate_message_3() {
            Err(OwnError(b)) => {
                stream.write(&b).expect("error during write");
                return None},
            Ok(val) => val,
        };

    // Packing message 3 into a phypayload and sending it
    let phypayload2 = prepare_edhoc_message(2, fcnt_up, Some(devaddr), msg3_bytes);
    fcnt_up += 1;
    stream.write(&phypayload2).expect("error during write");


    // read message 4

    let mut buf = [0;128];

    let bytes_read = stream.read(&mut buf).expect("error during read");
    let phypayload3 = &buf[0..bytes_read];

    if phypayload3[0] != 3 {
        let err = build_error_message("bad mtype");
        stream.write(&err).expect("error during write");
        return None
    }
    let msg4 = extract_edhoc_message(phypayload3)?;
    let out = msg4_receiver_verifier.handle_message_4(msg4.edhoc_msg);


    let (ed_sck,ed_rck,ed_rk) = match out {
        Err(OwnOrPeerError::PeerError(s)) => {
            println!("received error {} in message 4, shutting down", s);
            return None
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            stream.write(&b).expect("error during write");
            return None
        }
        Ok(val) => val,
    };

    Some((ed_sck,ed_rck,ed_rk, devaddr.to_vec()))
}







#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn wifi(
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    default_nvs: Arc<EspDefaultNvs>,
) -> Result<Box<EspWifi>> {
    let mut wifi = Box::new(EspWifi::new(netif_stack, sys_loop_stack, default_nvs)?);

    println!("Wifi created, about to scan");

    let ap_infos = wifi.scan()?;

    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);

    let channel = if let Some(ours) = ours {
        println!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        println!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.into(),
            password: PASS.into(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".into(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    println!("Wifi configuration set, about to get status");

    wifi.wait_status_with_timeout(Duration::from_secs(20), |status| !status.is_transitional())
        .map_err(|e| anyhow::anyhow!("Unexpected Wifi status: {:?}", e))?;

    let status = wifi.get_status();

    if let Status(
        ClientStatus::Started(ClientConnectionStatus::Connected(ClientIpStatus::Done(ip_settings))),
        ApStatus::Started(ApIpStatus::Done),
    ) = status
    {
        println!("Wifi connected");

        ping(&ip_settings)?;
    } else {
        println!("Unexpected Wifi status: {:?}", status);
    }

    Ok(wifi)
}


fn ping(ip_settings: &ipv4::ClientSettings) -> Result<()> {
    println!("About to do some pings for {:?}", ip_settings);

    let ping_summary =
        ping::EspPing::default().ping(ip_settings.subnet.gateway, &Default::default())?;
    if ping_summary.transmitted != ping_summary.received {
        println!(
            "Pinging gateway {} resulted in timeouts",
            ip_settings.subnet.gateway
        );
        main();
    }

    println!("Pinging done");

    Ok(())
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