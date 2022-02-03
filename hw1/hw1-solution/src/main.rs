use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::error::Error;
use std::time::Instant;
use std::collections::HashSet;
use rayon::prelude::*;

fn main() {
    let mut uncracked: HashSet<String> = HashSet::new(); // Set of hashes
    let mut words: Vec<String> = Vec::new(); // Vec of words

    // Read the password file into a hashset
    read_pass_file(&mut uncracked).expect("Unable to parse file!");
    // Read the wordlist into a vector
    read_wordlist(&mut words).expect("Unable to read file!");

    let now = Instant::now(); // Start timer
    for i in 0..words.len() {
        (i..words.len()).into_par_iter()
            .for_each(|j|
            if uncracked
                .contains(&format!("{:x}", salty_hash(&words[i], &words[j]))) {
                    let elapsed = now.elapsed();
                    let items = (i * words.len()) + j;
                    println!("Salt: {}", words[j]);
                    println!("Time elapsed: {:.2?}", elapsed);                
                    println!("Passwords: {}", uncracked.len());
                    println!("Wordlist size: {}", words.len());
                    println!("Items hashed: {}", items);
                    panic!("All Done!");
                    //return;
            });
    }

    //println!("Wordlist size: {}", words.len());
    //println!("Passwords: {}", uncracked.len());
}

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

fn salty_hash(item: &str, salt: &str) -> md5::Digest {
    let mut to_hash: String = String::from(item);
    to_hash.push_str(salt);
    md5::compute(to_hash)
}

#[test]
fn empty() {
    let empty = salty_hash("", "");
    assert_eq!(format!("{:x}", empty), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn item_only() {
    let item_only = salty_hash("abandoned", "");
    assert_eq!(format!("{:x}", item_only), "81f3d2a447d9c5579b446ff048827de1");
}

#[test]
fn salted_item() {
    let item_salt = salty_hash("idaho", "saturn");
    assert_eq!(format!("{:x}", item_salt), "81d4ce3fd1613924ed42bb4928c7e645");
}

