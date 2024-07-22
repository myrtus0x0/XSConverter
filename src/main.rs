use std::io::Error;
use std::{env, fs};

use nom::combinator::map;
use nom::complete::take;
use nom::multi::many_m_n;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use nom::IResult;

#[derive(Debug, Default)]
struct XsModule {
    magic: u16,
    nt_magic: u16,
    section_count: u16,
    imp_key: u16,
    hdr_size: u16,
    unk1: u16,
    module_size: u32,
    entry_point: u32,
    import_header: XsDataDir,
    exception_header: XsDataDir,
    reloc_header: XsDataDir,
    sections: Vec<XsSection>,
}

#[derive(Debug, Default)]
struct XsSection {
    rva: u32,
    raw: u32,
    size: u32,
    flags: u32,
}

#[derive(Debug, Default)]
struct XsDataDir {
    size: u32,
    rva: u32,
}

#[derive(Debug, Default)]
struct XsImports {
    dll_name_rva: u32,
    first_thunk: u32,
    original_first_thunk: u32,
    dll_length: u32,
}

impl XsModule {
    fn new(module_buffer: &[u8]) -> Result<Self, String> {
        let (remaining_data, mut module) = Self::parse_header(module_buffer).unwrap();

        let (remaining_data, import_header) = Self::parse_data_table(remaining_data).unwrap();
        module.import_header = import_header;

        let (remaining_data, exception_header) = Self::parse_data_table(remaining_data).unwrap();
        module.exception_header = exception_header;

        let (remaining_data, reloc_header) = Self::parse_data_table(remaining_data).unwrap();
        module.reloc_header = reloc_header;

        let (remaining_data, sections) =
            Self::parse_sections(module.section_count as usize, remaining_data).unwrap();

        if module_buffer.len() - remaining_data.len() != module.hdr_size as usize {
            dbg!(
                "still more header to parse: {}",
                module_buffer.len() - remaining_data.len()
            );
        } else {
            dbg!("no more header data!");
        }
        Ok(module)
    }

    fn parse_header(module_buffer: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((
                le_u16, le_u16, le_u16, le_u16, le_u16, le_u16, le_u32, le_u32,
            )),
            |(
                magic,
                nt_magic,
                section_count,
                imp_key,
                hdr_size,
                unk1,
                module_size,
                entry_point,
            )| XsModule {
                magic,
                nt_magic,
                section_count,
                imp_key,
                hdr_size,
                unk1,
                module_size,
                entry_point,
                import_header: XsDataDir::default(),
                exception_header: XsDataDir::default(),
                reloc_header: XsDataDir::default(),
                sections: Vec::new(),
            },
        )(module_buffer)
    }

    fn parse_data_table(module_buffer: &[u8]) -> IResult<&[u8], XsDataDir> {
        map(tuple((le_u32, le_u32)), |(size, rva)| XsDataDir {
            size,
            rva,
        })(module_buffer)
    }

    fn parse_import(import_buffer: &[u8]) -> IResult<&[u8], XsImports> {
        map(
            tuple((le_u32, le_u32, le_u32, le_u32)),
            |(dll_name_rva, first_thunk, original_first_thunk, dll_length)| XsImports {
                dll_name_rva,
                first_thunk,
                original_first_thunk,
                dll_length,
            },
        )(import_buffer)
    }

    fn parse_sections(
        num_sections: usize,
        section_buffer: &[u8],
    ) -> IResult<&[u8], Vec<XsSection>> {
        many_m_n(1, num_sections, |current_section| {
            map(
                tuple((le_u32, le_u32, le_u32, le_u32)),
                |(rva, raw, size, flags)| XsSection {
                    rva,
                    raw,
                    size,
                    flags,
                },
            )(current_section)
        })(section_buffer)
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
