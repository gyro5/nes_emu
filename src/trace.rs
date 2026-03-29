use crate::{
    cpu::CPU,
    mem::{AddressingMode, Mem},
    opcode::OPCODES_TABLE,
};

pub fn trace(cpu: &mut CPU) -> String {
    let opcode_table = &(*OPCODES_TABLE);

    // Get the next opcode details
    let code = cpu.mem_read(cpu.pc);
    let operand1 = cpu.mem_read(cpu.pc + 1);
    let operand2 = cpu.mem_read(cpu.pc + 2);
    let one_byte_operand = format!("{operand1:02X}");
    let two_byte_operand = format!("{operand1:02X} {operand2:02X}");
    let opcode = opcode_table
        .get(&code)
        .unwrap_or_else(|| panic!("Opcode {code:x} not recognized."));

    let mode = &opcode.mode;
    let op_addr = if let &AddressingMode::NoneAddressing = mode {
        0xFFFF
    } else {
        // A bit hacky to not have to rewrite the get_operand_address function
        cpu.pc += 1;
        let addr = cpu.get_operand_address(mode);
        cpu.pc -= 1;
        addr
    };

    let (operand_bytes, details) = match mode {
        AddressingMode::Immediate => (one_byte_operand, format!("#${operand1:02X}")),

        AddressingMode::ZeroPage => (
            one_byte_operand,
            format!("${operand1:02X} = {:02X}", cpu.mem_read(operand1 as u16)),
        ),

        AddressingMode::ZeroPageX => (
            one_byte_operand,
            format!(
                "${:02X},X @ {:02X} = {:02X}",
                operand1,
                operand1 + cpu.register_x,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::ZeroPageY => (
            one_byte_operand,
            format!(
                "${:02X},Y @ {:02X} = {:02X}",
                operand1,
                operand1 + cpu.register_y,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::Absolute => (two_byte_operand, format!("${operand2:02X}{operand1:02X}")),

        AddressingMode::AbsoluteX => (
            two_byte_operand,
            format!(
                "${:02X}{:02X},X @ {:04X} = {:02X}",
                operand2,
                operand1,
                op_addr,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::AbsoluteY => (
            two_byte_operand,
            format!(
                "${:02X}{:02X},Y @ {:04X} = {:02X}",
                operand2,
                operand1,
                op_addr,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::IndirectX => (
            one_byte_operand,
            format!(
                "(${operand1:02X},X) @ {:02X} = {:04X} = {:02X}",
                operand1.wrapping_add(cpu.register_x),
                op_addr,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::IndirectY => (
            one_byte_operand,
            format!(
                "(${operand1:02X}),Y = {:04X} @ {:04X} = {:02X}",
                cpu.mem_read_u16(operand1 as u16),
                op_addr,
                cpu.mem_read(op_addr)
            ),
        ),

        AddressingMode::NoneAddressing => ("".to_string(), "".to_string()),
    };

    format!(
        "{:04X}  {:02X} {:6} {} {:27} A:{:02X} X:{:02X} Y:{:02X} P:{:02X} SP:{:02X}",
        cpu.pc,
        code,
        operand_bytes,
        opcode.name,
        details,
        cpu.register_a,
        cpu.register_x,
        cpu.register_y,
        cpu.status.bits(),
        cpu.sp
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bus::Bus;
    use crate::mem::Mem;
    use crate::rom::test::dummy_rom;

    #[test]
    fn test_format_trace() {
        let mut bus = Bus::new(dummy_rom());
        bus.mem_write(100, 0xa2);
        bus.mem_write(101, 0x01);
        bus.mem_write(102, 0xca);
        bus.mem_write(103, 0x88);
        bus.mem_write(104, 0x00);

        let mut cpu = CPU::new(bus);
        cpu.pc = 0x64;
        cpu.register_a = 1;
        cpu.register_x = 2;
        cpu.register_y = 3;
        let mut result: Vec<String> = vec![];
        cpu.run_with_callback(|cpu| {
            result.push(trace(cpu));
        });
        assert_eq!(
            "0064  A2 01     LDX #$01                        A:01 X:02 Y:03 P:24 SP:FD",
            result[0]
        );
        assert_eq!(
            "0066  CA        DEX                             A:01 X:01 Y:03 P:24 SP:FD",
            result[1]
        );
        assert_eq!(
            "0067  88        DEY                             A:01 X:00 Y:03 P:26 SP:FD",
            result[2]
        );
    }

    #[test]
    fn test_format_mem_access() {
        let mut bus = Bus::new(dummy_rom());
        // ORA ($33), Y
        bus.mem_write(100, 0x11);
        bus.mem_write(101, 0x33);

        //data
        bus.mem_write(0x33, 0x00);
        bus.mem_write(0x34, 0x04);

        //target cell
        bus.mem_write(0x400, 0xAA);

        let mut cpu = CPU::new(bus);
        cpu.pc = 0x64;
        cpu.register_y = 0;
        let mut result: Vec<String> = vec![];
        cpu.run_with_callback(|cpu| {
            result.push(trace(cpu));
        });
        assert_eq!(
            "0064  11 33     ORA ($33),Y = 0400 @ 0400 = AA  A:00 X:00 Y:00 P:24 SP:FD",
            result[0]
        );
    }
}
