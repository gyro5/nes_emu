use crate::mem::{AddressingMode, Mem};
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
    #[derive(Clone)]
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
    pub sp: u8,        // Stack pointer
    mem: [u8; 0xFFFF], // 64 KiB of RAM
}

// NES 6502 CPU uses stack from 0x1FF to 0x100, but the initial sp is 0xFD
// --> See: https://www.nesdev.org/wiki/CPU_power_up_state
const STACK_RESET: u8 = 0xFD;
const STACK_BASE: u16 = 0x100;

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
            sp: STACK_RESET,
            mem: [0; 0xFFFF],
        }
    }

    /// Reset the register state of the CPU and load the starting program address
    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0b0010_0100);
        self.sp = STACK_RESET;

        self.pc = self.mem_read_u16(0xFFFC);
    }

    /// Push 1 byte to the stack
    fn stack_push(&mut self, byte: u8) {
        // Note: sp will always point to the next slot to be used
        self.mem_write(STACK_BASE + self.sp as u16, byte);
        self.sp = self.sp.wrapping_sub(1); // Stack grows down
    }

    // Pop 1 byte from the stack
    fn stack_pop(&mut self) -> u8 {
        // The value to read is the one right above sp
        self.sp = self.sp.wrapping_add(1);
        self.mem_read(STACK_BASE + self.sp as u16)
    }

    /// Push 2 bytes to the stack
    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    // Pop 2 bytes from the stack
    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;
        hi << 8 | lo
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

    /// Add the offset from the next byte to pc if condition is true
    fn branch_if(&mut self, condition: bool) {
        if condition {
            // Need "as i8" to get the negative jump offset, then when cast to u16,
            // the leftmost bit (which is 1) will be extended.
            // If go from u8 straight to u16, the leftmost bits will be 0 (0-extend).
            let offset = self.mem_read(self.pc) as i8;
            self.pc = self.pc.wrapping_add(1).wrapping_add(offset as u16);
        }
    }

    /// Compare a value in memory with a register value
    fn compare(&mut self, reg: u8, mode: &AddressingMode) {
        let value = self.get_byte_by_addr_mode(mode);
        self.update_zero_and_neg_flags(reg.wrapping_sub(value));
        if reg >= value {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
    }

    /// Load a program to the memory
    pub fn load(&mut self, program: Vec<u8>) {
        // Load the program to a hardcoded address for now
        self.mem[0x0600..(0x0600 + program.len())].copy_from_slice(&program);
        // NES uses 0xFFFC to store program's start address
        self.mem_write_u16(0xFFFC, 0x0600);
    }

    /// Run with no callback
    pub fn run(&mut self) {
        self.run_with_callback(|_| {});
    }

    /// Run the given program with the callback being called before each instruction
    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where
        F: FnMut(&mut CPU),
    {
        let opcode_table = &(*OPCODES_TABLE);

        loop {
            // Run the callback first
            callback(self);

            // Get the next opcode
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

                // BCC - Branch if carry clear
                0x90 => self.branch_if(!self.status.contains(CpuFlags::CARRY)),

                // BCS - Branch if carry set
                0xB0 => self.branch_if(self.status.contains(CpuFlags::CARRY)),

                // BEQ - Branch if equal (zero)
                0xF0 => self.branch_if(self.status.contains(CpuFlags::ZERO)),

                // BIT - Bit test
                0x24 | 0x2C => {
                    let arg = self.get_byte_by_addr_mode(mode);
                    let result = arg & self.register_a;
                    self.update_zero_and_neg_flags(result);
                    if result & 0b0100_0000 != 0 {
                        self.status.insert(CpuFlags::OVERFLOW);
                    } else {
                        self.status.remove(CpuFlags::OVERFLOW);
                    }
                }

                // BMI - Branch if minus
                0x30 => self.branch_if(self.status.contains(CpuFlags::NEGATIVE)),

                // BNE - Branch if not equal
                0xD0 => self.branch_if(!self.status.contains(CpuFlags::ZERO)),

                // BPL - Branch if positive
                0x10 => self.branch_if(!self.status.contains(CpuFlags::NEGATIVE)),

                // BRK - Break program
                0x00 => {
                    println!("Done running!");
                    return;
                }

                // BVC - Branch if overflow clear
                0x50 => self.branch_if(!self.status.contains(CpuFlags::OVERFLOW)),

                // BVS - Branch if overflow set
                0x70 => self.branch_if(self.status.contains(CpuFlags::OVERFLOW)),

                // CLC - Clear carry flag
                0x18 => self.status.remove(CpuFlags::CARRY),

                // CLD - Clear decimal mode (decimal mode not used on NES)
                0xD8 => self.status.remove(CpuFlags::DECIMAL_MODE),

                // CLI - Clear interupt disable
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),

                // CLV - Clear overflow flag
                0xB8 => self.status.remove(CpuFlags::OVERFLOW),

                // CMP - Compare with reg A
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
                    self.compare(self.register_a, mode);
                }

                // CPX - Compare with reg X
                0xE0 | 0xE4 | 0xEC => {
                    self.compare(self.register_x, mode);
                }

                // CPY - Compare with reg Y
                0xC0 | 0xC4 | 0xCC => {
                    self.compare(self.register_y, mode);
                }

                // DEC - Decrement memory
                0xC6 | 0xD6 | 0xCE | 0xDE => {
                    let addr = self.get_operand_address(mode);
                    let value = self.mem_read(addr);
                    let result = value.wrapping_sub(1);
                    self.mem_write(addr, result);
                    self.update_zero_and_neg_flags(result);
                }

                // DEX - Decrement reg X
                0xCA => self.set_reg_x(self.register_x.wrapping_sub(1)),

                // DEY - Decrement reg Y
                0x88 => self.set_reg_y(self.register_y.wrapping_sub(1)),

                // EOR - XOR reg A and memory
                0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_a(self.register_a ^ value);
                }

                // INC - Increment memory
                0xE6 | 0xF6 | 0xEE | 0xFE => {
                    let addr = self.get_operand_address(mode);
                    let value = self.mem_read(addr);
                    let result = value.wrapping_add(1);
                    self.mem_write(addr, result);
                    self.update_zero_and_neg_flags(result);
                }

                // INX - Increment reg X
                0xE8 => self.set_reg_x(self.register_x.wrapping_add(1)),

                // INY - Increment reg Y
                0xC8 => self.set_reg_y(self.register_y.wrapping_add(1)),

                // JMP - Jump to address
                0x4C | 0x6C => {
                    let addr = self.mem_read_u16(self.pc);
                    self.pc = addr;
                    // Note: Indirect jump might have problem
                    // --> See: https://www.nesdev.org/obelisk-6502-guide/reference.html#JMP
                }

                // JMP - Jump with 6502 bug - NOT NEEDED FOR NOW
                // 0x6C => {
                //     let mem_address = self.mem_read_u16(self.pc);
                //     // let indirect_ref = self.mem_read_u16(mem_address);
                //     //6502 bug mode with with page boundary:
                //     //  if address $3000 contains $40, $30FF contains $80, and $3100 contains $50,
                //     // the result of JMP ($30FF) will be a transfer of control to $4080 rather than $5080 as you intended
                //     // i.e. the 6502 took the low byte of the address from $30FF and the high byte from $3000

                //     let indirect_ref = if mem_address & 0x00FF == 0x00FF {
                //         let lo = self.mem_read(mem_address);
                //         let hi = self.mem_read(mem_address & 0xFF00);
                //         (hi as u16) << 8 | (lo as u16)
                //     } else {
                //         self.mem_read_u16(mem_address)
                //     };

                //     self.pc = indirect_ref;
                // }

                // JSR - Jump to subroutine
                0x20 => {
                    // Note: pc is already incremented and points to the address to jump to
                    // after the opcode is read.
                    let next_pc = self.pc + 2;
                    self.stack_push_u16(next_pc - 1);
                    self.pc = self.mem_read_u16(self.pc);
                }

                // LDA - Load to reg A
                0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_a(value);
                }

                // LDX - Load to reg X
                0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_x(value);
                }

                // LDY - Load to reg Y
                0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_y(value);
                }

                // LSR - Logical right shift to reg A
                0x4A => {
                    // Bit 0 (to be shifted away) is put in CARRY
                    if self.register_a & 0b0000_0001 != 0 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }

                    // Logical shift fills left space with 0
                    self.set_reg_a(self.register_a >> 1);
                }

                // LSR - Logical right shift to memory
                0x46 | 0x56 | 0x4E | 0x5E => {
                    let addr = self.get_operand_address(mode);
                    let value = self.mem_read(addr);
                    if value & 0b0000_0001 != 0 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }

                    let result = value >> 1;
                    self.mem_write(addr, result);
                    self.update_zero_and_neg_flags(result);
                }

                // NOP - No op
                0xEA => {}

                // ORA - Logical OR
                0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 => {
                    let value = self.get_byte_by_addr_mode(mode);
                    self.set_reg_a(self.register_a | value);
                }

                // PHA - Push reg A to stack
                0x48 => {
                    self.stack_push(self.register_a);
                }

                // PHP - Push status byte to stack
                0x08 => {
                    let mut flags = self.status.clone();

                    // 2 break flags always pushed as on.
                    // --> See: https://www.nesdev.org/wiki/Status_flags
                    flags.insert(CpuFlags::BREAK);
                    flags.insert(CpuFlags::BREAK2);

                    self.stack_push(flags.bits());
                }

                // PLA - Pop stack to reg A
                0x68 => {
                    let value = self.stack_pop();
                    self.set_reg_a(value);
                }

                // PLP - Pop stack to status
                0x28 => {
                    let value = self.stack_pop();
                    self.status = CpuFlags::from_bits_retain(value);
                    self.status.remove(CpuFlags::BREAK);
                    self.status.remove(CpuFlags::BREAK2);
                }

                // ROL - Rotate left reg A
                0x2A => {
                    let carry_bit = if self.status.contains(CpuFlags::CARRY) {
                        1
                    } else {
                        0
                    };
                    if self.register_a >> 7 == 1 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }
                    self.set_reg_a((self.register_a << 1) | carry_bit);
                }

                // ROL - Rotate left memory
                0x26 | 0x36 | 0x2E | 0x3E => {
                    let addr = self.get_operand_address(mode);
                    let value = self.mem_read(addr);

                    let carry_bit = if self.status.contains(CpuFlags::CARRY) {
                        1
                    } else {
                        0
                    };
                    if value >> 7 == 1 {
                        self.status.insert(CpuFlags::CARRY);
                    } else {
                        self.status.remove(CpuFlags::CARRY);
                    }

                    let result = (value << 1) | carry_bit;
                    self.mem_write(addr, result);
                    self.update_zero_and_neg_flags(result);
                }

                // RTI - Return from interrupt
                0x40 => {
                    // From https://github.com/bugzmanov/nes_ebook/blob/master/code/ch3.3/src/cpu.rs#L709C21-L711C58
                    self.status = CpuFlags::from_bits_retain(self.stack_pop());
                    self.status.remove(CpuFlags::BREAK);
                    self.status.insert(CpuFlags::BREAK2);
                    self.pc = self.stack_pop_u16();
                }

                // RTS - Return from subroutine
                0x60 => {
                    // Because the return address pushed to stack is 1 before
                    // the address of the next instruction.
                    self.pc = self.stack_pop_u16() + 1;
                }

                // SBC - Subtract with carry
                0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {
                    // Subtract is plus the two complements of the operand
                    let value = self.get_byte_by_addr_mode(mode) as i8;
                    self.add_to_reg_a(value.wrapping_neg().wrapping_sub(1) as u8);
                }

                // SEC- Set carry
                0x38 => self.status.insert(CpuFlags::CARRY),

                // SED - Set decimal flag
                0xF8 => self.status.insert(CpuFlags::DECIMAL_MODE),

                // SEI - Set interupt disable
                0x78 => self.status.insert(CpuFlags::INTERRUPT_DISABLE),

                // STA - Store from A to memory
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    let addr = self.get_operand_address(mode);
                    self.mem_write(addr, self.register_a);
                }

                // STX - Store from X to memory
                0x86 | 0x96 | 0x8E => {
                    let addr = self.get_operand_address(mode);
                    self.mem_write(addr, self.register_x);
                }

                // STY - Store from Y to memory
                0x84 | 0x94 | 0x8C => {
                    let addr = self.get_operand_address(mode);
                    self.mem_write(addr, self.register_y);
                }

                // TAX - Transfer A to X
                0xAA => self.set_reg_x(self.register_a),

                // TAY - Transfer A to Y
                0xA8 => self.set_reg_y(self.register_a),

                // TSX - Transfer sp to X
                0xBA => self.set_reg_x(self.sp),

                // TXA - Transfer X to A
                0x8A => self.set_reg_a(self.register_x),

                // TXS - Transfer X to sp
                0x9A => self.sp = self.register_x,

                // TYA - Transfer Y to A
                0x98 => self.set_reg_a(self.register_y),

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
