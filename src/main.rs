use std::io::Error;
use std::{env, fs};

use nom::combinator::map;
use nom::complete::take;
use nom::multi::many_m_n;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use nom::IResult;

#[derive(Debug)]
struct XsModule {
    magic: u16,
    header_size: u16,
    section_count: u16,
    imp_key: u16,
    module_size: u32,
    entry_point: u32,
    entry_point_alt: u32,
    imports: Vec<XsImports>,
    // exceptions,
    // relocs,
    // sections
}

#[derive(Debug)]
struct XsImports {
    dll_name_rva: u32,
    first_thunk: u32,
    original_first_thunk: u32,
    dll_length: [u8; 2],
}

impl XsModule {
    fn new(module_buffer: &[u8]) -> Result<Self, String> {
        let (remaining_data, mut module) = Self::parse_header(module_buffer).unwrap();
        let (remaining_data, imports) = Self::parse_imports(usize::from(module.section_count), remaining_data).unwrap();

        module.imports = imports;
        Ok(module)
    }

    fn parse_header(module_buffer: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((le_u16, le_u16, le_u16, le_u16, le_u32, le_u32, le_u32)),
            |(
                magic,
                header_size,
                section_count,
                imp_key,
                module_size,
                entry_point,
                entry_point_alt,
            )| XsModule {
                magic,
                header_size,
                section_count,
                imp_key,
                module_size,
                entry_point,
                entry_point_alt,
                imports: Vec::new(),
            },
        )(module_buffer)
    }

    fn parse_imports(section_count: usize, module_buffer: &[u8]) -> IResult<&[u8], Vec<XsImports>> {
        many_m_n(1, section_count, Self::parse_import)(module_buffer)
    }

    fn parse_import(import_buffer: &[u8]) -> IResult<&[u8], XsImports> {
        map(
            tuple((le_u32, le_u32, le_u32)),
            |(dll_name_rva, first_thunk, original_first_thunk)| XsImports {
                dll_name_rva,
                first_thunk,
                original_first_thunk,
                dll_length: [0, 0]
            },
        )(import_buffer)
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Error::new(
            std::io::ErrorKind::NotFound,
            "file path to XS module required",
        ));
    }

    let f_contents = fs::read(&args[1])?;
    dbg!(f_contents.len());

    if let Ok(module) = XsModule::new(&f_contents) {
        dbg!(module);
    }
    Ok(())
}
