fn main() {
    prost_build::compile_protos(&["proto/qday.proto"], &["proto/"]).unwrap();
}
