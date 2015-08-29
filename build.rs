extern crate gcc;

fn main() {
    gcc::Config::new()
            .file("src/randombytes.c")
            .file("src/tweetnacl.c")
            .compile("libtweetnacl.a"); 
}
