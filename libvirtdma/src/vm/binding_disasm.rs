use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction};
use crate::vm::VMBinding;

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

use colored::{ColoredString, Colorize};
use iced_x86::{
    FormatterOutput, FormatterTextKind, IntelFormatter,
};

// Custom formatter output that stores the output in a vector.
struct MyFormatterOutput {
    vec: Vec<(String, FormatterTextKind)>,
}

impl MyFormatterOutput {
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }
}

impl FormatterOutput for MyFormatterOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        // This allocates a string. If that's a problem, just call print!() here
        // instead of storing the result in a vector.
        self.vec.push((String::from(text), kind));
    }
}


fn print_disasm(bytes: &[u8], rip: u64) {
    let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
    decoder.set_ip(rip);

    // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED)
    let mut formatter = IntelFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    // String implements FormatterOutput
    let mut output = MyFormatterOutput::new();

    // Initialize this outside the loop because decode_out() writes to every field
    let mut instruction = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (32 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        // Format the instruction ("disassemble" it)
        output.vec.clear();
        formatter.format(&instruction.into(), &mut output);

        // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - rip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        for (text, kind) in output.vec.iter() {
            print!("{}", get_color(text.as_str(), *kind));
        }
        println!();
    }
}

fn get_color(s: &str, kind: FormatterTextKind) -> ColoredString {
    match kind {
        FormatterTextKind::Directive | FormatterTextKind::Keyword => s.bright_yellow(),
        FormatterTextKind::Prefix | FormatterTextKind::Mnemonic => s.bright_red(),
        FormatterTextKind::Register => s.bright_blue(),
        FormatterTextKind::Number => s.bright_cyan(),
        _ => s.white(),
    }
}

impl VMBinding {
    pub fn vpdisasm(&self, dtb: u64, address: u64, len: u64, rip: u64) {
        let data = self.vreadvec(dtb, address, len);
        print_disasm(&data, rip);
    }
}