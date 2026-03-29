pub mod cpu;
pub mod opcode;
pub mod mem;
pub mod snake;
pub mod bus;
pub mod rom;
pub mod trace;

fn main() {
    snake::run();
}
