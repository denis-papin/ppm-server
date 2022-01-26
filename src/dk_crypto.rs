use std::iter::repeat;
use std::ops::Add;
use std::fs::File;
use std::io::{BufReader};
use std::io::Read;

use rustc_serialize;
use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE, STANDARD};

use crypto;
use crypto::aes::{self};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::md5::Md5;
use crypto::{  symmetriccipher, buffer, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::symmetriccipher::SymmetricCipherError;

use crate::dk_crypto_error;
use crate::dk_crypto_error::*;

// Ensure the constant is obfuscated in the binary code.
const SALT : obfstr::ObfString<[u8; 100]> = obfstr::obfconst!("vg6E748cXiifSsnErGlXr5KHXN35ANmUoa2VRiebAmllCKCxItIvYZXlqCYGl0BfAzJQ4hIzbrcbISZ07yxA8G9W9x7hbZKVekpX");

pub(crate) struct DkEncrypt {

}

/* Public routines */
impl DkEncrypt {

    pub fn encrypt_vec(clear_data: &Vec<u8>, key : &str  ) -> Result<Vec<u8>, SymmetricCipherError> {
        let iv = get_iv();
        let vec_key =  key.from_base64().unwrap();
        let slice_key = &vec_key[..];
        let slice_clear : &[u8] = &clear_data[..];
        let r_encrypted = encrypt(slice_clear, slice_key, &iv);

        r_encrypted
    }

    /**
    */
    pub fn decrypt_vec(encrypted_data : &Vec<u8>, key : &str  ) -> Result<Vec<u8>, SymmetricCipherError> {
        let iv = get_iv();
        let vec_key =  key.from_base64().unwrap();
        let slice_key = &vec_key[..];
        let slice_encrypted : &[u8] = &encrypted_data[..];
        let r_decrypted = decrypt(slice_encrypted, slice_key, &iv);

        r_decrypted
    }

    /**
    */
    pub fn encrypt_str(clear_txt : &str, key : &str  ) -> String {
        let clear_data = clear_txt.to_string().into_bytes();
        let encrypted_data = DkEncrypt::encrypt_vec(&clear_data, key);

        match encrypted_data {
            Ok(v) => {
                v.to_base64(URL_SAFE)
            },
            Err(e) => {
                // TODO
                eprint!("Error {:?}", e);
                "".to_string()
            }
        }
    }


//  We want "AES/CBC/PKCS5PADDING"
//  base64 url key : O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU
//  crypted text : 5eftIdP8d4MFUU4KVUn-VQ3Tu_SACE47R01xt9KOhVCxGyVVRSn19yWnbXjOmg-cao6SW4itOM4cRUz33ZgQP_Ae5VtTmk-NsXtg5StaYlGX4QCljpO914xJkocNW_0TZCLvqzaNsTZKGzbPGXJlFMWy8JunbKMR1omkze5-w17Yxr2Gg1SpHU57SeqBCpvbkj5rMyF6skxp4LWMQzEBSj121n7VpXkmndtP-y4n7QOeQjTpW2tmXMhqpTyr-B5mhO7PXsMcNoIcWr7FCpGws14m_I8PNRaCN3nfpviXV5l1TbBa1noeE5HH0AFOs8IxqMLRmikA6bY8Av6IipDYnbZ7d2TO6SjGcE40Yvl3Z_e963Y4GLrbpnwj_9_V4_wNmUFROtj9AO5uRPzwEQdlKcGmiqfluTow-jG4ROJTnaggiCkaTEyFpcjhAye8VNahjo1rKBxecWzC1bp6SrH1-g-jFnMT5yrC7rko3fYvuN2LBpIldDziaJ3ahy3rRWIkelYIHigx6Zu__BZXSAkoKioQ6kvldsVDvFi1_NUISk3b9TOs5pNcopVJKhBEiJHoSUonICPj7UzxauyArh-RzNQQoZV19D03hXFNgXYJvPuXJ3upIpgFMaLC59NcAGZj0Q3H3uztAmkvpICr5Uv05FrmdiLKpN0lhKS0ETr2gVwuY_MRNTmI_V5Ud7SY6tutnLQtjrOFPNckPMQ1Yjyq_2b3FrClJ5fvunvfAEDh0RSKOx62GatWWtiuH7HDhkU_0pRC6QfnIL9W0W6YLnvlTKq_HaaVECuhp-PMRN6PQxkg5TOWOtjQ1IyvIosKfgBXhjyp5AhKlYevoOZqRyo0YxycviyCZUAq4-k5KzTaacDPMx_HYcpg0waPVIsE4DPtgLNQjDl2RaEGUKYntu89bYn47lFj3CP1j0umrWwJuJhznr5NtU7oxZ4Rlznq3lEjqNKkHnvUWD3Z8l68XWicvHWaZ9itH6IznD9GMksQYA-YbumI9wh4BIP1u1T-A9pHWRbWjpJP2sNVKMgLeIZhCy5go8uHDPIwNqTZFQLM59DtTrWCEJHQIP4KMabwHNDTBHvVQtn-EOQZP9kF7kMtYKsnmMlx12mS-fdG4qT_ko5zceYctXwiICT-DpWiRhfI2C29zRZqPLj0s3iuMo1xopL1fDX9b6gG2RywFZwZRtjEhiFi-lfpR-P7Jck61qu2V4sBx_OYNa78epKwelp6gwtSgmzOJjnPULmif9AL9HE

    pub fn decrypt_str(encrypted_text : &str, key : &str  ) -> Result<String, DkCryptoError > {


        // dbg!(&encrypted_text);

        let encrypted_data = encrypted_text.from_base64().unwrap();

        //// dbg!(&encrypted_data);
        // dbg!(&key);

        let decrypted_data = DkEncrypt::decrypt_vec(&encrypted_data, key);

        match decrypted_data {
            Ok(v) => {
                let s = String::from_utf8(v);
                println!("Decipher message 2 : {:?}",  &s  );
                Ok(s.unwrap_or("".to_string()))
            },
            Err(e) => {
                eprint!("Error {:?}", e);
                // TODO how to keep the original error
                Err( dk_crypto_error::DkCryptoError )
            }
        }
    }


    pub fn decrypt_customer_file(path : &str, master_key : &str ) -> Result<String, DkCryptoError > {

        //let file = File::open("C:/Users/denis/wks-steeple/tools/passinjector/data/debugCustomer.enc")?;
        let file = File::open(path).expect("Cannot read the customer file"); // TODO Error

        let mut buf_reader = BufReader::new(file);

        let mut buf : Vec<u8> = vec![];

        let _n = buf_reader.read_to_end(&mut buf).expect("Didn't read enough");

        let s = buf.to_base64(URL_SAFE);

        //// dbg!(&s);

        let bin_content = DkEncrypt::decrypt_vec(&buf, &master_key);

        let ret = match bin_content {
            Ok(v) => {
                Ok(String::from_utf8(v).unwrap_or("".to_string()))
            },
            Err(_e) => {
                // TODO LOG THE ERROR
                Err( dk_crypto_error::DkCryptoError )
            }
        };

        ret
    }

    pub fn _decrypt_file(path : &str,  master_key : &str ) -> Result<Vec<u8>, DkCryptoError> {

        //let file = File::open("C:/Users/denis/wks-steeple/tools/passinjector/data/debugCustomer.enc")?;
        let file = File::open(path).expect("Cannot read the customer file"); // TODO Error

        let mut buf_reader = BufReader::new(file);

        let mut buf : Vec<u8> = vec![];

        let _n = buf_reader.read_to_end(&mut buf).expect("Didn't read enough");

        let _s = buf.to_base64(URL_SAFE);

        // C:\Users\denis\wks-steeple\tools\passinjector\data\debugCustomer.enc
        // password : il faut viser la lune.... => + salt + hash

        // let master_key = DkEncrypt::get_master_key();

        // // dbg!(&s);

        let bin_content = DkEncrypt::decrypt_vec(&buf, &master_key);
        // // dbg!(&bin_content);

        let ret = match bin_content {
            Ok(v) => {
                Ok(v)
            },
            Err(_e) => {
                // TODO LOG THE ERROR
                Err( dk_crypto_error::DkCryptoError )
            }
        };

        ret
    }


    //
    // Used to hash passwords
    //
    pub fn hash_with_salt(password: &str ) -> String {
        let salty_password = password.to_string().add(get_salt().as_str());
        let mut sha = Sha256::new();
        sha.input_str(&salty_password);
        println!("sha : {}", sha.result_str());

        let mut bytes: Vec<u8> = repeat(0u8).take(sha.output_bytes()).collect();
        sha.result(&mut bytes[..]);

        let key = bytes.to_base64(URL_SAFE);

        println!("base 64 : {}", &key);

        key
    }


    /**
    */
    pub fn get_master_key() -> String {
        //let master_password = "Il faut viser la lune car même en cas d'échec on atterrit dans les étoiles";
        let master_password = "le roi des mots de passe";
        DkEncrypt::hash_with_salt(master_password)
    }

}  // trait DkEncrypt


/* Private routines */


// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    // Create an encryptor instance of the best performing
    // type available for the platform.
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

/**

*/
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding
        /*blockmodes::NoPadding */);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {

        let r_result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);

        let result = match r_result {
            Ok(result) => {
                result
            },
            Err(e) => {
                // // dbg!(String::from(&read_buffer));
                // error!(e);
                return Err(e);
            }
        };

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        //let d = String::from_utf8(final_result.to_owned());
        //// dbg!(d);
        // // dbg!(&final_result.len());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    // // dbg!(&final_result.len());

    Ok(final_result)
}


/**
*/
fn get_iv() -> [u8;16] {
    let mut md5 = Md5::new();
    md5.input_str(get_salt().as_str());
    let mut iv :[u8;16] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    md5.result(&mut iv);
    // println!( "get_iv = {:?}, {}", iv, iv.len() );
    iv
}

fn get_salt() -> String {
    String::from(SALT.deobfuscate(0).as_str())
}

#[test]
pub fn decrypt_encrypt()  {
    let encrypted = "5eftIdP8d4MFUU4KVUn-VQ3Tu_SACE47R01xt9KOhVCxGyVVRSn19yWnbXjOmg-cao6SW4itOM4cRUz33ZgQP_Ae5VtTmk-NsXtg5StaYlGX4QCljpO914xJkocNW_0TZCLvqzaNsTZKGzbPGXJlFMWy8JunbKMR1omkze5-w17Yxr2Gg1SpHU57SeqBCpvbkj5rMyF6skxp4LWMQzEBSj121n7VpXkmndtP-y4n7QOeQjTpW2tmXMhqpTyr-B5mhO7PXsMcNoIcWr7FCpGws14m_I8PNRaCN3nfpviXV5l1TbBa1noeE5HH0AFOs8IxqMLRmikA6bY8Av6IipDYnbZ7d2TO6SjGcE40Yvl3Z_e963Y4GLrbpnwj_9_V4_wNmUFROtj9AO5uRPzwEQdlKcGmiqfluTow-jG4ROJTnaggiCkaTEyFpcjhAye8VNahjo1rKBxecWzC1bp6SrH1-g-jFnMT5yrC7rko3fYvuN2LBpIldDziaJ3ahy3rRWIkelYIHigx6Zu__BZXSAkoKioQ6kvldsVDvFi1_NUISk3b9TOs5pNcopVJKhBEiJHoSUonICPj7UzxauyArh-RzNQQoZV19D03hXFNgXYJvPuXJ3upIpgFMaLC59NcAGZj0Q3H3uztAmkvpICr5Uv05FrmdiLKpN0lhKS0ETr2gVwuY_MRNTmI_V5Ud7SY6tutnLQtjrOFPNckPMQ1Yjyq_2b3FrClJ5fvunvfAEDh0RSKOx62GatWWtiuH7HDhkU_0pRC6QfnIL9W0W6YLnvlTKq_HaaVECuhp-PMRN6PQxkg5TOWOtjQ1IyvIosKfgBXhjyp5AhKlYevoOZqRyo0YxycviyCZUAq4-k5KzTaacDPMx_HYcpg0waPVIsE4DPtgLNQjDl2RaEGUKYntu89bYn47lFj3CP1j0umrWwJuJhznr5NtU7oxZ4Rlznq3lEjqNKkHnvUWD3Z8l68XWicvHWaZ9itH6IznD9GMksQYA-YbumI9wh4BIP1u1T-A9pHWRbWjpJP2sNVKMgLeIZhCy5go8uHDPIwNqTZFQLM59DtTrWCEJHQIP4KMabwHNDTBHvVQtn-EOQZP9kF7kMtYKsnmMlx12mS-fdG4qT_ko5zceYctXwiICT-DpWiRhfI2C29zRZqPLj0s3iuMo1xopL1fDX9b6gG2RywFZwZRtjEhiFi-lfpR-P7Jck61qu2V4sBx_OYNa78epKwelp6gwtSgmzOJjnPULmif9AL9HE";
    let clear = DkEncrypt::decrypt_str(encrypted, "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");
    // dbg!(&clear);

    let new_encrypted = DkEncrypt::encrypt_str(&clear.unwrap(), "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");

    // dbg!(&new_encrypted);
    assert_eq!(&encrypted, &new_encrypted);
}

#[test]
pub fn encrypt_decrypt()  {
    let clear = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config>\n   <customers>\n      <customer name=\"doka.live\">\n         <cipheredPassword>KgnCdO4pwroiQQfkve7lwtAOClu4N4MgKmpYvsOF5Xodq1EZT_vdeQ_Y_XSj53w8</cipheredPassword>\n         <enabled>true</enabled>\n         <masterKeyHash>gjzLNyQzpZtYOv_Z5XXAJhVdlrJ1X0nZQsHOGCiYmWU</masterKeyHash>\n      </customer>\n      <customer name=\"[[P2_MESSAGE]]\">\n         <cipheredPassword>NCEOHZq19Ta5VK7XkGZPTSP-lOBwkKzCn0DRPl0SKDJ3lsIRxsPUFBq6wNWW-Uiw</cipheredPassword>\n         <enabled>true</enabled>\n         <masterKeyHash>gjzLNyQzpZtYOv_Z5XXAJhVdlrJ1X0nZQsHOGCiYmWU</masterKeyHash>\n      </customer>\n      <customer name=\"SYSTEM\">\n         <cipheredPassword>DSnE3j0m9IqHzdNkAbFNw1So_CawWiUHxfHfJmdDIzjsBoRAXWwDWWITZH1pYXdQ</cipheredPassword>\n         <enabled>true</enabled>\n         <masterKeyHash>gjzLNyQzpZtYOv_Z5XXAJhVdlrJ1X0nZQsHOGCiYmWU</masterKeyHash>\n      </customer>\n   </customers>\n</config>\n";
    let encrypted = DkEncrypt::encrypt_str(clear, "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");

    // dbg!(&encrypted);

    let new_clear = DkEncrypt::decrypt_str(&encrypted, "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");
    // dbg!(&new_clear);

    assert_eq!(&clear, &new_clear.unwrap());
}

#[test]
pub fn encrypt_decrypt_2()  {
    let clear = "hello3xxx";
    let encrypted = DkEncrypt::encrypt_str(clear, "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");

    // dbg!(&encrypted);

    let new_clear = DkEncrypt::decrypt_str(&encrypted, "O27AYTdNPNbG-7olPOUxDNb6GNnVzZpbGRa4qkhJ4BU");
    // dbg!(&new_clear);

    assert_eq!(&clear, &new_clear.unwrap());
}