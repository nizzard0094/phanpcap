use std::env;

fn main() {
    let libdir = env::var("PCAP_LIBDIR").unwrap();
    println!("cargo:rustc-link-search=native={}", libdir);
    println!("cargo:rustc-link-lib=static=packet");
    println!("cargo:rustc-link-lib=static=wpcap");
}
