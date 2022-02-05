use std::env;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};

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
    fn contains(&self, other: &str) -> bool {
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

fn hasher_md5(in_pass: String, in_salt: &str) -> String {
    let str_cat = in_pass + in_salt;
    let new_hash = md5::compute(&str_cat);
    format!("{:x}", new_hash)
}

fn cracking_time(accounts: &mut Vec<Account>, words: &[String], known_salt: Option<String>) {
    let mut hash: String = "".to_owned();

    let quicker = match known_salt.as_ref() {
        Some(_k) => true,
        None => false,
    };

    if quicker {
        for i in words {
            hash = hasher_md5(i.to_string(), &known_salt.as_ref().unwrap());
            for acc in &mut *accounts {
                if acc.contains(&hash) {
                    acc.password = i.to_string();
                    acc.salt = known_salt.as_ref().unwrap().to_string();
                    println!("{:#?}", acc);
                    break;
                }
            }
        }
    } else {
        for i in 0..words.len() {
            for k in i..words.len() {
                hash = hasher_md5(words[i].to_string(), &words[k]);
                for acc in &mut *accounts {
                    if acc.contains(&hash) {
                        acc.password = words[i].to_string();
                        acc.salt = words[k].to_string();
                        println!("{:#?}", acc);
                        break;
                    }
                }
            }
        }
    }
}

fn main() {
    let mut accounts = load_accounts();
    let words = load_wordlist();
    cracking_time(&mut accounts, &words, env::args().nth(3));
    //println!("{:#?}", accounts);
    println!("All Done!");
}
