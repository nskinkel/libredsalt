extern crate gcc;

fn main() {
    gcc::compile_library("libtweetnacl.a", &["src/lib/tweetnacl-20140427.c"]);
}
