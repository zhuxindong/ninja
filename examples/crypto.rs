fn main() {
    let x = openai::arkose::murmur::murmurhash3_x64_128(b"test", 31);
    // ff55565a476832ed3409c64597508ca4
    println!("{:x}{:x}", x.0, x.1);

    let encode = openai::arkose::crypto::encrypt("Hello, World", "my_secret_key").unwrap();
    println!("encode: {encode}");
    let decode = openai::arkose::crypto::decrypt(encode.into_bytes(), "my_secret_key").unwrap();
    println!("decode: {decode}");
}
