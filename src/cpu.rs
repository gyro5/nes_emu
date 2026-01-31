use crate::opcode::OPCODES_TABLE;
use bitflags::bitflags;

bitflags! {
    /// # Status Register (P) http://wiki.nesdev.com/w/index.php/Status_flags
    ///
    ///  7 6 5 4 3 2 1 0
    ///  N V _ B D I Z C
    ///  | |   | | | | +--- Carry Flag
    ///  | |   | | | +----- Zero Flag
    ///  | |   | | +------- Interrupt Disable
    ///  | |   | +--------- Decimal Mode (not used on NES)
    ///  | |   +----------- Break Command
    ///  | +--------------- Overflow Flag
    ///  +----------------- Negative Flag
    ///
    pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100; // On to allow interupt
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000; // On bc unused
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub status: CpuFlags,
    pub pc: u16,
    mem: [u8; 0xFFFF], // 64 KiB of RAM
}

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

trait Mem {
    fn mem_read(&self, addr: u16) -> u8;

    fn mem_write(&mut self, addr: u16, data: u8);

    /// Read 2 bytes from the memory
    fn mem_read_u16(&self, addr: u16) -> u16 {
        // Address is in little-endian
        let lo = self.mem_read(addr) as u16;
        let hi = self.mem_read(addr + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    /// Write 2 bytes to the memory
    fn mem_write_u16(&mut self, addr: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(addr, lo);
        self.mem_write(addr + 1, hi);
    }
}

impl Mem for CPU {
    /// Return a byte at addr from the memory
    fn mem_read(&self, addr: u16) -> u8 {
        self.mem[addr as usize]
    }

    /// Write a byte to the address addr in the memory
    fn mem_write(&mut self, addr: u16, data: u8) {
        self.mem[addr as usize] = data;
    }
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            status: CpuFlags::from_bits_truncate(0b0010_0100),
            pc: 0,
            mem: [0; 0xFFFF],
        }
    }

    /// Get the address of the operand, depending on the addressing mode
    fn get_operand_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.pc,

            AddressingMode::ZeroPage => self.mem_read(self.pc) as u16,

            AddressingMode::ZeroPageX => {
                let addr = self.mem_read(self.pc);
                addr.wrapping_add(self.register_x) as u16
            }

            AddressingMode::ZeroPageY => {
                let addr = self.mem_read(self.pc);
                addr.wrapping_add(self.register_y) as u16
            }

            AddressingMode::Absolute => self.mem_read_u16(self.pc),

            AddressingMode::AbsoluteX => {
                let addr = self.mem_read_u16(self.pc);
                addr.wrapping_add(self.register_x as u16)
            }

            AddressingMode::AbsoluteY => {
                let addr = self.mem_read_u16(self.pc);
                addr.wrapping_add(self.register_y as u16)
            }

            AddressingMode::IndirectX => {
                let base = self.mem_read(self.pc);
                let ptr_to_addr = base.wrapping_add(self.register_x);

                let lo = self.mem_read(ptr_to_addr as u16) as u16;
                let hi = self.mem_read(ptr_to_addr.wrapping_add(1) as u16) as u16;
                hi << 8 | lo
            }

            AddressingMode::IndirectY => {
                let ptr_to_base = self.mem_read(self.pc);

                let lo = self.mem_read(ptr_to_base as u16) as u16;
                let hi = self.mem_read(ptr_to_base.wrapping_add(1) as u16) as u16;

                let base = hi << 8 | lo;
                base.wrapping_add(self.register_y as u16)
            }

            AddressingMode::NoneAddressing => {
                panic!("Mode {mode:?} is not supported.")
            }
        }
    }

    /// Reset the register state of the CPU and load the starting program address
    fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b0010_0100);

        self.pc = self.mem_read_u16(0xFFFC);
    }

    /// Load a program to the memory
    pub fn load(&mut self, program: Vec<u8>) {
        // Load the program to the address 0x8000
        self.mem[0x8000..(0x8000 + program.len())].copy_from_slice(&program);
        self.mem_write_u16(0xFFFC, 0x8000); // NES uses 0xFFFC to store program's start addr
    }

    /// Set the zero flag and negative flag according to the result
    fn update_zero_and_neg_flags(&mut self, result: u8) {
        // Zero flag
        if result == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        // Negative flag
        if result & 0b1000_0000 != 0 {
            self.status.insert(CpuFlags::NEGATIVE);
        } else {
            self.status.remove(CpuFlags::NEGATIVE);
        }
    }

    fn set_reg_a(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_neg_flags(self.register_a);
    }

    fn set_reg_x(&mut self, value: u8) {
        self.register_x = value;
        self.update_zero_and_neg_flags(self.register_x);
    }

    fn set_reg_y(&mut self, value: u8) {
        self.register_y = value;
        self.update_zero_and_neg_flags(self.register_y);
    }

    fn get_byte_by_addr_mode(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_address(mode);
        self.mem_read(addr)
    }

    fn get_2_bytes_by_addr_mode(&mut self, mode: &AddressingMode) -> u16 {
        let addr = self.get_operand_address(mode);
        self.mem_read_u16(addr)
    }

    /// Add to register A and set the Z, N, O, C flags
    fn add_to_reg_a(&mut self, operand: u8) {
        let prev_carry: u16 = if self.status.contains(CpuFlags::CARRY) {
            1
        } else {
            0
        };

        // Carry is when unsigned addition results in > 255 (0xFF)
        let u16_sum: u16 = self.register_a as u16 + operand as u16 + prev_carry;
        if u16_sum > 0xFF {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }

        // Overflow: use formular from
        // https://www.righto.com/2012/12/the-6502-overflow-flag-explained.html
        let sum = u16_sum as u8; // "as" will truncate the value
        if (self.register_a ^ sum) & (operand ^ sum) ^ 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW);
        } else {
            self.status.remove(CpuFlags::OVERFLOW);
        }

        self.set_reg_a(sum);
    }

    /// Run the given program
    pub fn run(&mut self) {
        let opcode_table = &(*OPCODES_TABLE);

        loop {
            let code = self.mem_read(self.pc);
            self.pc += 1;
            let save_pc = self.pc;

            let opcode = opcode_table
                .get(&code)
                .expect(&format!("Opcode {code:x} not recognized."));
            let mode = &opcode.mode;

            match code {
                // ADC - Add with carry to reg A
                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.add_to_reg_a(value);
                }

                // AND - Logical AND with reg A
                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_a(value & self.register_a);
                }

                // ASL - Arithmetic Shift Left to reg A
                0x0A => {
                    // Carry is the highest bit of reg A
                    if self.register_a >> 7 == 1 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }

                    self.set_reg_a(self.register_a << 1);
                }

                // ASL - Arithmetic Shift Left to memory
                0x06 | 0x16 | 0x0E | 0x1E => {
                    let addr = self.get_operand_address(mode);
                    let value = self.mem_read(addr);

                    // Carry (this is different from Rust's overflowing_shl)
                    if value >> 7 == 1 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }

                    let result = value << 1;
                    self.mem_write(addr, result);
                    self.update_zero_and_neg_flags(result);
                }

                // LDA - Load to A
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_a(value);
                }

                // STA - Store from A to memory
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    let addr = self.get_operand_address(mode);
                    self.mem_write(addr, self.register_a);
                }

                // TAX - Take A to X
                0xAA => {
                    self.set_reg_x(self.register_a);
                }

                // INX - Increment X
                0xe8 => {
                    // Increment and allow overflow (but don't set overflow flag)
                    self.set_reg_x(self.register_x.wrapping_add(1));
                }

                // BRK - Break program
                0x00 => {
                    return;
                }

                _ => todo!(),
            }

            // Increment pc according to OpCode size if didn't jump
            if self.pc == save_pc {
                self.pc += (opcode.len - 1) as u16;
            }
        }
    }

    /// Load a program to memory and run it
    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 0x05);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b00);
        assert!(cpu.status.bits() & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status.bits() & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_lda_from_memory() {
        let mut cpu = CPU::new();
        cpu.mem_write(0x10, 0x55);

        cpu.load_and_run(vec![0xa5, 0x10, 0x00]);

        assert_eq!(cpu.register_a, 0x55);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x12, 0xaa, 0x00]);
        assert_eq!(cpu.register_x, 0x12)
    }

    #[test]
    fn test_5_ops_working_together() {
        // LDA #$c0
        // TAX
        // INX
        // BRK
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }
}
