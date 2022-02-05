use std::{env, io};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;
use rayon::prelude::*;

#[allow(dead_code)]
#[derive(Debug)]
struct Account {
    uid: u16,
    uname: String,
    email: String,
    hash: String,
    salt: String,
    password: String,
}

impl Account {
    fn contains_hash(&self, other: &str) -> bool {
        self.hash == other
    }
}

fn parse_passfile(path: &str) -> Result<Vec<Account>, io::Error> {
    let file = File::open(path)?;
    let mut rdr = csv::Reader::from_reader(file);
    let mut account_vec = Vec::new();

    for rec in rdr.records() {
        let item = rec?;
        let new_account = Account {
            uid: item[0].parse::<u16>().unwrap(),
            uname: item[2].to_string(),
            email: item[3].to_string(),
            hash: item[4].to_string(),
            salt: "".to_string(),
            password: "".to_string(),
        };
        account_vec.push(new_account);
    }
    Ok(account_vec)
}

fn load_accounts() -> Vec<Account> {
    let pass_path = env::args().nth(1).expect("Pass file not found!");
    parse_passfile(&pass_path).expect("Unable to parse file!")
}

fn parse_wordlist(path: &str) -> Result<Vec<String>, io::Error> {
    let mut words = Vec::new();
    let file = File::open(path)?;
    let rdr = BufReader::new(file);

    for lines in rdr.lines() {
        for word in lines.unwrap().split_whitespace() {
            words.push(word.to_string());
        }
    }
    Ok(words)
}

fn load_wordlist() -> Vec<String> {
    let word_path = env::args().nth(2).expect("Word file not found!");
    parse_wordlist(&word_path).expect("Unable to parse file!")
}

fn hasher_md5(in_pass: &str, in_salt: &str) -> String {
    let str_cat = in_pass.to_string() + in_salt;
    let new_hash = md5::compute(&str_cat);
    format!("{:x}", new_hash)
}

fn find_salt<'a>(user: &Account, words : &'a [String]) -> Option<&'a String> {
    for i in words {
        let a = words.par_iter().find_any(|a| {
            user.hash == hasher_md5(i, a)
        });
        if a.is_some() {return a;}
    }
    None
    // for i in words {
    //     for j in words {
    //         if user.hash == hasher_md5(i, j) {
    //             return Some(j);
    //         }
    //     }
    // }
    // None
}

fn find_password<'a> (user: &Account, words: &'a [String], salt: & str) -> Option<&'a String> {
    let a = words.par_iter()
        .find_any(|a| {
            user.hash == hasher_md5(a, salt)
        });
    if a.is_some() {return a;}
    None

    // for i in words {
    //     if user.hash == hasher_md5(i, salt) {
    //         return Some(i);
    //     }
    // }
    // None
}

fn cracking_time(accounts: &mut Vec<Account>, words: &[String]) {
    let mut salt: &str = &find_salt(&accounts[0], words).unwrap();

    for i in 0..accounts.len() {
        match find_password(&accounts[i], words, &salt) {
            Some(s) => {
                accounts[i].salt = salt.to_string();
                accounts[i].password = s.to_string();
                continue;
            },
            None => {
                salt = &find_salt(&accounts[i], words).unwrap();
                accounts[i].password = find_password(&accounts[i], words, &salt).unwrap().to_string();
                accounts[i].salt = salt.to_string();
            }
        };
    }
}

fn main() {
    let mut accounts = load_accounts();
    let words = load_wordlist();

    let now = Instant::now();
    cracking_time(&mut accounts, &words);
    let elapsed = now.elapsed();

    println!("{:#?}", accounts);
    println!("Execution Time: {:.2?}", elapsed);
    println!("All Done!");
}
