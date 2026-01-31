pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub status: u8,
    pub pc: u8,
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            status: 0,
            pc: 0,
        }
    }

    /// Set the zero flag and negative flag according to the result
    fn update_zero_and_neg_flags(&mut self, result: u8) {
        // Zero flag
        if result == 0 {
            self.status |= 0b0000_0010;
        } else {
            self.status &= 0b1111_1101;
        }

        // Negative flag
        if result & 0b1000_0000 != 0 {
            self.status |= 0b1000_0000;
        } else {
            self.status &= 0b0111_1111;
        }
    }

    fn lda(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_neg_flags(self.register_a);
    }

    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zero_and_neg_flags(self.register_x);
    }

    fn inx(&mut self) {
        // Increment and allow overflow (but don't set overflow flag)
        self.register_x = self.register_x.wrapping_add(1);
        self.update_zero_and_neg_flags(self.register_x);
    }

    /// Run the given program
    pub fn interpret(&mut self, program: Vec<u8>) {
        self.pc = 0;

        loop {
            let opcode = program[self.pc as usize];
            self.pc += 1;

            match opcode {
                // LDA - Load to A
                0xA9 => {
                    let param = program[self.pc as usize];
                    self.pc += 1;

                    self.lda(param);
                }

                // TAX - Take A to X
                0xAA => self.tax(),

                // INX - Increment X
                0xe8 => self.inx(),

                // BRK - Break program
                0x00 => {
                    return;
                }

                _ => todo!(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_0xa9_lda_immediate_load_data() {
        let mut cpu = CPU::new();
        cpu.interpret(vec![0xa9, 0x05, 0x00]);
        assert_eq!(cpu.register_a, 0x05);
        assert!(cpu.status & 0b0000_0010 == 0b00);
        assert!(cpu.status & 0b1000_0000 == 0);
    }

    #[test]
    fn test_0xa9_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.interpret(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b0000_0010 == 0b10);
    }

    #[test]
    fn test_0xaa_tax_move_a_to_x() {
        let mut cpu = CPU::new();
        cpu.register_a = 10;
        cpu.interpret(vec![0xaa, 0x00]);

        assert_eq!(cpu.register_x, 10)
    }

    #[test]
    fn test_5_ops_working_together() {
        // LDA #$c0
        // TAX
        // INX
        // BRK
        let mut cpu = CPU::new();
        cpu.interpret(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 0xc1)
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.register_x = 0xff;
        cpu.interpret(vec![0xe8, 0xe8, 0x00]);

        assert_eq!(cpu.register_x, 1)
    }
}
