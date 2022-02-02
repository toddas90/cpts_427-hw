fn main() {
    println!("Hello, world!");
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

