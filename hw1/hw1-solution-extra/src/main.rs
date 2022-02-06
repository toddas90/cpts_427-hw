use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;
use std::{env, fmt, io};

// Made a struct to store the user info from the
// password file. Only decided to store the important
// information.
struct Account {
    uid: u16,
    uname: String,
    email: String,
    hash: String,
    salt: String,
    password: String,
}

// Implementing the display trait for my
// struct.
impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "user: {}\n    uid: {}\n    email: {}\n    password: {}\n",
            self.uname, self.uid, self.email, self.password
        )
    }
}

// Opens the file and parses the information into the Account
// struct. Returns a Vec of Accounts or an Err().
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

// Parses the wordlist into a Vec of Strings. Each element is 
// a different word.
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

// Wrapper function to load the password file data. Takes in a string (path)
// and passes it to the parsing function. Returns a Vec of Accounts.
fn load_accounts() -> Vec<Account> {
    let pass_path = env::args().nth(1).expect("Pass file not found!");
    parse_passfile(&pass_path).expect("Unable to parse file!")
}

// Wrapper function for loading the wordlist into a Vec. Takes the
// path to the worlist and passes it to the parsing function. Returns
// the Vec of words.
fn load_wordlist() -> Vec<String> {
    let word_path = env::args().nth(2).expect("Word file not found!");
    parse_wordlist(&word_path).expect("Unable to parse file!")
}

// Hashing function. Takes a password, a salt, and returns the hash in
// String format.
fn hasher_md5(in_pass: &str, in_salt: &str) -> String {
    let str_cat = in_pass.to_string() + in_salt;
    let new_hash = md5::compute(&str_cat);
    format!("{:x}", new_hash)
}

// Finds the salt that was used to encrypt a user's password. Returns
// the String if it finds it, or None if it doesn't find it.
fn find_salt<'a>(user: &Account, words: &'a [String]) -> Option<&'a String> {
    for i in words {
        let a = words.par_iter().find_any(|a| user.hash == hasher_md5(i, a));
        if a.is_some() {
            return a;
        }
    }
    None
}

// Finds the user's unencrypted password given an account, a wordlist, and a salt.
// Returns the password if it is found, or None if not.
fn find_password<'a>(user: &Account, words: &'a [String], salt: &str) -> Option<&'a String> {
    words
        .par_iter()
        .find_any(|a| user.hash == hasher_md5(a, salt))
}

// Main password cracking function. Takes in a vector of Accounts, a wordlist in
// vector form, and runs find_salt and find_password on each Account.
// It finds a random salt to start and tries it on a user. If it works, it tries
// it on the next one. Once it finds an Account that doesn't use that salt, it finds
// a new salt and uses that one instead.
fn cracking_time(accounts: &mut Vec<Account>, words: &[String]) {
    let mut salt = find_salt(&accounts[0], words).unwrap();

    for user in accounts {
        match find_password(user, words, salt) {
            Some(s) => {
                user.salt = salt.to_string();
                user.password = s.to_string();
                continue;
            }
            None => {
                salt = find_salt(user, words).unwrap();
                user.password = find_password(user, words, salt).unwrap().to_string();
                user.salt = salt.to_string();
            }
        };
    }
}

// Load Accounts from file into a Vec, load words from file into Vec, then cracks
// the hashes and prints them out.
fn main() {
    let mut accounts = load_accounts();
    let words = load_wordlist();

    let now = Instant::now();
    cracking_time(&mut accounts, &words);
    let elapsed = now.elapsed();

    for acc in accounts {
        println!("{}", acc);
    }
    println!("\nExecution Time: {:.2?}", elapsed);
    println!("All Done!");
}
