use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use error::ErrorStack;
use x509::X509;
use stack::{Stack, StackRef, Stackable};
// use std::ptr;
use std::vec;

use bio::MemBioSlice;

use cvt_p;

// #[cfg(test)]
// mod tests;

foreign_type! { 
    type CType = ffi::pkcs7;
    fn drop = ffi::pkcs7_free;

    pub struct Pkcs7Vector;
    pub struct Pkcs7VectorRef;
}

struct EnvelopedData(*mut ffi::pkcs7);

impl Pkcs7VectorRef {
  // check types
//   fn encrypt(mime: &[u8], certs: *mut ffi::stack_st_X509, cipher: *mut ffi::EVP_CIPHER) -> Result<ffi::pkcs7, ErrorStack> {
  pub fn encrypt(mime: &[u8], certs: *mut &X509, cipher: *mut ffi::EVP_CIPHER) -> Result<EnvelopedData, ErrorStack> {
    unsafe {
            let bio = MemBioSlice::new(mime)?;
            let flags: i32 = 0;

            let certs = if certs.is_null() {
                Stack::new()?
            } else {
                Stack::from_ptr(certs)
            };

            // let something: Stack<X509> = certs.as_ref();
            // let something: Stack<X509> = Stack::from_ptr(certs as *mut X509);
            // let something: Stack<X509> = Stack::from_ptr(certs.as_mut_ptr());
            // Stack::from_ptr(certs.as_mut_ptr());
            // let certs: ffi::stack_st_X509 = certs;
            // let certs = X509::from_ptr(certs);

            let encrypted = cvt_p(ffi::PKCS7_encrypt(
                certs.as_ptr(),
                bio.as_ptr(),
                cipher,
                flags.into()
            ))?;

            // Ok(Pkcs7VectorRef::from_ptr_mut(encrypted))
            Ok(EnvelopedData(encrypted))
            // Ok(ffi::pkcs7::from_ptr(encrypted))
        }
  }
}

#[cfg(test)]
mod tests {
    use x509::X509;
    use dsa::Dsa;
    use symm::Cipher;
    // use stack::Stack;
    // use std::ptr;

    #[test]
    fn smime_test() {
    // Encrypt data, decrypt sdata, sign data and verify sdata.
    //
    // 1: let data: Vec<u8> = !vec[104, 101, 108, 108, 111]
    // 2: let data: String = String::from("foo")
    //
    // assert_eq!(data, decrypted);


    // let certs = include_bytes!("../../test/certs.pem");
    // let certs = X509::stack_from_pem(certs).unwrap();
    let cert = include_bytes!("../../test/certs.pem");
    let cert = X509::from_pem(cert).unwrap();

    let key = Dsa::generate(2048).unwrap();
    let pem = key.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar")
        .unwrap();
    let message: String = String::from("foo");

    let encrypted = super::Pkcs7VectorRef::encrypt(message.as_bytes(), &cert, pem);
    assert_eq!(encrypted, b"hello");
    }
}
