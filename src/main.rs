pub mod cpu;
pub mod opcode;

fn main() {
    println!("Test {:b}", 0b1000_0000_u8 >> 1);
}
