use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::error::Error;
use std::time::Instant;
use std::collections::HashSet;
use rayon::prelude::*;

/// Create a hashset and a vector for storage. Then read the data in from
/// their respective files. Should be (password file, wordlist). Then it runs
/// the bruteforce algorithm to find the salt that was used to hash the passwords.
/// It uses a for loop to iterate through the wordlist, then a parallel for loop
/// inside to iterate through the wordlist again. The outer loop represents the
/// strings, and the inner loop represents the salts. It hashes them together
/// and it checks to see if that is one of the salted hashes from the password
/// file. If so, the salt has been found and it exits.
fn main() {
    let mut uncracked: HashSet<String> = HashSet::new(); // Set of hashes
    let mut words: Vec<String> = Vec::new(); // Vec of words

    // Read the password file into a hashset
    read_pass_file(&mut uncracked).expect("Unable to parse file!");
    // Read the wordlist into a vector
    read_wordlist(&mut words).expect("Unable to read file!");

    let now = Instant::now(); // Start timer
    for i in 0..words.len() { // Sequential for loop
        (i..words.len()).into_par_iter().for_each(|j| // Parallel for loop
            if uncracked.contains(&format!("{:x}", salty_hash(&words[i], &words[j]))) {
                let elapsed = now.elapsed(); // Get execution time
                let items = (i * words.len()) + j; // Get num of iterations
                println!("Salt: {}", words[j]); // Print salt
                println!("Time elapsed: {:.2?}", elapsed); // Print time               
                println!("Passwords: {}", uncracked.len()); // Print num passwords
                println!("Wordlist size: {}", words.len()); // Print num words
                println!("Items hashed: {}", items); // Print the num of interations
                panic!("All Done!"); // Panic because I don't know how to exit a parallel loop ;)
            });
    }
}

/// Read the wordlist into a vector for easy traversal.
/// It assumes that the wordlist is the 2nd argument provided.
fn read_wordlist(invec: &mut Vec<String>) -> Result<(), Box<dyn Error>> {
    let wordlist_path = env::args().nth(2).expect("Wordlist not provided!");
    let reader = BufReader::new(File::open(wordlist_path)?);

    for line in reader.lines() {
        for word in line.unwrap().split_whitespace() {
            invec.push(word.to_string());
        }
    }
    Ok(())
}

/// Read the password file and parse the salted hashes into a hashset for
/// quick searching. The passwords are the 4th element in our schema.
/// Expects the password file to be the 1st argument
fn read_pass_file(inset: &mut HashSet<String>) -> Result<(), Box<dyn Error>> {
    let pass_file_path = env::args().nth(1).expect("Hash file not provided!");
    let password_file = File::open(pass_file_path)?;

    let mut rdr = csv::Reader::from_reader(password_file);
    for result in rdr.records() {
        let test = result?;
        inset.insert(test[4].to_string());
    }
    Ok(())
}

/// My wrapper around an md5 hash crate that I found. It takes in a password
/// string and a salt string, then it concatinates them and hashes the new
/// string.
fn salty_hash(item: &str, salt: &str) -> md5::Digest {
    let mut to_hash: String = String::from(item);
    to_hash.push_str(salt);
    md5::compute(to_hash)
}

/// Test for empty string and empty salt.
#[test]
fn empty() {
    let empty = salty_hash("", "");
    assert_eq!(format!("{:x}", empty), "d41d8cd98f00b204e9800998ecf8427e");
}

/// Test for string but no salt.
#[test]
fn item_only() {
    let item_only = salty_hash("abandoned", "");
    assert_eq!(format!("{:x}", item_only), "81f3d2a447d9c5579b446ff048827de1");
}

/// Test for string and salt.
#[test]
fn salted_item() {
    let item_salt = salty_hash("idaho", "saturn");
    assert_eq!(format!("{:x}", item_salt), "81d4ce3fd1613924ed42bb4928c7e645");
}

