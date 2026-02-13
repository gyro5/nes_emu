#[derive(Debug)]
pub enum AddressingMode {
    Immediate,      // Address is the pc (operand is next byte)
    ZeroPage,       // Address in the first mem page (first 256 bytes)
    ZeroPageX,      // ZeroPage + Offset in reg X
    ZeroPageY,      // ZeroPage + Offset in reg Y
    Absolute,       // Use next 2 bytes as address
    AbsoluteX,      // Absolute + Offset in reg X
    AbsoluteY,      // Absolute + Offset in reg Y
    IndirectX,      // Next byte + X as pointer to the address
    IndirectY,      // Next byte as pointer to the address, then + offset Y
    NoneAddressing, // No address
}

pub trait Mem {
    /// Return a byte at addr from the memory
    fn mem_read(&self, addr: u16) -> u8;

    /// Write a byte to the address addr in the memory
    fn mem_write(&mut self, addr: u16, data: u8);

    /// Read 2 bytes from the memory
    fn mem_read_u16(&self, addr: u16) -> u16 {
        // Address is in little-endian
        let lo = self.mem_read(addr) as u16;
        let hi = self.mem_read(addr + 1) as u16;
        (hi << 8) | lo
    }

    /// Write 2 bytes to the memory
    fn mem_write_u16(&mut self, addr: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(addr, lo);
        self.mem_write(addr + 1, hi);
    }
}
