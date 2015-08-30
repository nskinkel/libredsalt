extern crate gcc;

fn main() {
    gcc::compile_library("libtweetnacl.a",
        &["src/randombytes.c", "src/tweetnacl.c"]);
}
