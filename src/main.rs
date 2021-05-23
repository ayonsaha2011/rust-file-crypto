extern crate crypto;
extern crate base64;
extern crate clap;

use std::fs::File;
use std::io::Read;
use std::io::Write;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use clap::{Arg, App};

// Encrypt a buffer with the given key and iv using
// AES-256 encryption.
fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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
        let result =encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256 encryption.
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let app = App::new("File-Crypto")
        .version("1.0")
        .author("Ayon Saha <ayonsaha2011@gmail.com>");

    let type_option = Arg::with_name("type")
        .long("type") // allow --type
        .short("t ") // allow --t
        .takes_value(true)
        .help("process type encrypt/decrypt")
        .required(true);

    let password_option = Arg::with_name("password")
        .long("password") // allow --password
        .short("p ") // allow --p
        .takes_value(true)
        .help("password for encrypt/decrypt. Password length should be 32 letters.")
        .required(true);

    let files_count_option = Arg::with_name("files_count")
        .long("files_count") // allow --files_count
        .takes_value(true)
        .help("number of files for encrypt/decrypt")
        .required(true);

    let filenames_option = Arg::with_name("filenames")
        .long("filenames") // allow --filenames
        .multiple(true)
        .min_values(1)
        .help("filenames in the current directory for encrypt/decrypt. example: --filenames a.txt b.txt c.txt ")
        .required(true);

    let app = app
        .arg(type_option)
        .arg(password_option)
        .arg(files_count_option)
        .arg(filenames_option);

    let matches = app.get_matches();


    let pt = matches.value_of("type").unwrap();
    let password = matches.value_of("password").unwrap().to_owned();
    let _files_count = matches.value_of("files_count").unwrap().to_string().parse::<usize>().unwrap();
    let filenames: Vec<_> = matches.values_of("filenames").unwrap().collect();

    let iv: [u8; 16] = [206, 123, 140, 64, 162, 28, 7, 252, 53, 211, 45, 217, 223, 64, 126, 199];
    let key= password.as_bytes();

    if  key.len() == 32 as usize {
        let fnames = filenames.to_owned();
        for fname in fnames {
            let process_type = pt.to_string();
            let filename = fname.to_owned();
            let mut f = File::open(&filename).expect("no file found");
            let mut src = Vec::<u8>::new();
            f.read_to_end(&mut src).expect("buffer overflow");

            let mut file = File::create(format!("{}.{}", &filename, &process_type)).unwrap();

            let data = match process_type.as_str() {
                "encrypt" => {
                    let encrypted_data = encrypt(&*src, &key, &iv).ok().unwrap();
                    let encrypted_str = base64::encode(&encrypted_data);
                    encrypted_str
                },
                "decrypt" => {
                    let src_data = base64::decode(src).unwrap();
                    let decrypted_data = decrypt(&src_data, &key, &iv).ok().unwrap();
                    let s = String::from_utf8_lossy(&*decrypted_data).to_string();
                    s
                },
                _ => "".to_string()
            };
            file.write_all(&data.as_bytes()).unwrap();
        }
    } else {
        println!("Password length should be 32 letters.");
    }
    Ok(())
}


