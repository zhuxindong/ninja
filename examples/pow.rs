use sha2::{Digest, Sha256};
use std::time::SystemTime;

const PREFIX_LENGTH: usize = 5; // 调整这个值来增加/减少挑战的难度

pub struct ProofOfWork {
    pub data: String,
    pub difficulty: usize,
}

impl ProofOfWork {
    pub fn new(data: String, difficulty: usize) -> Self {
        ProofOfWork { data, difficulty }
    }

    pub fn calculate(&self) -> (u64, String) {
        let mut nonce = 0u64;
        loop {
            let input = format!("{}{}", self.data, nonce);
            let hash = hex::encode(Sha256::digest(input.as_bytes()));
            if &hash[..self.difficulty] == &"0".repeat(self.difficulty) {
                return (nonce, hash);
            }
            nonce += 1;
        }
    }

    pub fn valid(&self) -> bool {
        let input = format!("{}{}", self.data, self.calculate().0);
        let hash = hex::encode(Sha256::digest(input.as_bytes()));
        &hash[..self.difficulty] == &"0".repeat(self.difficulty)
    }
}

fn main() {
    let now = SystemTime::now();

    let pow = ProofOfWork::new("some data".into(), PREFIX_LENGTH);
    let (nonce, hash) = pow.calculate();

    let elapsed = now.elapsed().unwrap();
    println!("Found nonce: {}, hash: {}", nonce, hash);
    println!("Time elapsed: {:.2?}", elapsed);
}
