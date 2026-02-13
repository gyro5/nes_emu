pub mod cpu;
pub mod opcode;
pub mod mem;
pub mod snake;
pub mod rom;

fn main() {
    snake::run();
}
