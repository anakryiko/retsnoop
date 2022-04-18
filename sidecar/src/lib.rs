extern crate addr2line;
extern crate fallible_iterator;
extern crate gimli;
extern crate memmap;
extern crate object;
extern crate typed_arena;

use std::borrow::Cow;
use std::fs::File;
//use std::io::{BufRead, Lines, StdinLock, Write};
use std::path::Path;

//use fallible_iterator::FallibleIterator;
//use glob;
use object::{Object, ObjectSection}; //, SymbolMap, SymbolMapName};
use typed_arena::Arena;

use addr2line::{Context, Location};

use libc::c_char;
use std::ffi::CStr;
use std::ptr;

struct Config {
    do_functions: bool,
    do_inlines: bool,
    pretty: bool,
    print_addrs: bool,
    basenames: bool,
    demangle: bool,
    llvm: bool,
}

struct Sidecar {
    cfg: Config,
    ctx: Context<gimli::EndianSlice<'static, gimli::RunTimeEndian>>,
}

fn print_loc(loc: &Option<Location>, basenames: bool, llvm: bool) {
    if let Some(ref loc) = *loc {
        let file = loc.file.as_ref().unwrap();
        let path = if basenames {
            Path::new(Path::new(file).file_name().unwrap())
        } else {
            Path::new(file)
        };
        print!("{}:", path.display());
        if llvm {
            print!("{}:{}", loc.line.unwrap_or(0), loc.column.unwrap_or(0));
        } else if let Some(line) = loc.line {
            print!("{}", line);
        } else {
            print!("?");
        }
        println!();
    } else if llvm {
        println!("??:0:0");
    } else {
        println!("??:?");
    }
}

fn print_function(name: &str, language: Option<gimli::DwLang>, demangle: bool) {
    if demangle {
        print!("{}", addr2line::demangle_auto(Cow::from(name), language));
    } else {
        print!("{}", name);
    }
}

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
) -> Result<gimli::EndianSlice<'arena, Endian>, ()> {
    // TODO: Unify with dwarfdump.rs in gimli.
    let name = id.name();
    match file.section_by_name(name) {
        Some(section) => match section.uncompressed_data().unwrap() {
            Cow::Borrowed(b) => Ok(gimli::EndianSlice::new(b, endian)),
            Cow::Owned(b) => Ok(gimli::EndianSlice::new(arena_data.alloc(b.into()), endian)),
        },
        None => Ok(gimli::EndianSlice::new(&[][..], endian)),
    }
}

impl Sidecar {
    fn new(path: &str, inlines: bool) -> Sidecar {
        let arena_data = Arena::new();

        let file = File::open(path).unwrap();
        let map = unsafe { memmap::Mmap::map(&file).unwrap() };
        let object = &object::File::parse(&*map).unwrap();

        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let mut load_section = |id: gimli::SectionId| -> Result<_, _> {
            load_file_section(id, object, endian, &arena_data)
        };

        //let sup_map;
        //let sup_object = if let Some(sup_path) = matches.value_of("sup") {
        //let sup_file = File::open(sup_path).unwrap();
        //sup_map = unsafe { memmap::Mmap::map(&sup_file).unwrap() };
        //Some(object::File::parse(&*sup_map).unwrap())
        //} else {
        //None
        //};

        let symbols = object.symbol_map();
        let mut dwarf = gimli::Dwarf::load(&mut load_section).unwrap();
        //if let Some(ref sup_object) = sup_object {
        //let mut load_sup_section = |id: gimli::SectionId| -> Result<_, _> {
        //load_file_section(id, sup_object, endian, &arena_data)
        //};
        //dwarf.load_sup(&mut load_sup_section).unwrap();
        //}

        let ctx = Context::from_dwarf(dwarf).unwrap();
        let cfg = Config {
            llvm: true,
            do_functions: true,
            do_inlines: inlines,
            pretty: false,
            print_addrs: false,
            basenames: false,
            demangle: false,
        };
        return Sidecar { cfg, ctx };
    }
}

#[no_mangle]
pub unsafe extern "C" fn init_sidecar(vmlinux_path: *const c_char, inlines: bool) -> *mut Sidecar {
    if vmlinux_path.is_null() {
        return ptr::null_mut();
    }

    let raw_path = CStr::from_ptr(vmlinux_path);
    let path_str = match raw_path.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let sidecar = Sidecar::new(path_str, inlines);
    Box::into_raw(Box::new(sidecar))
}

#[no_mangle]
pub unsafe extern "C" fn free_sidecar(sidecar: *mut Sidecar) {
    if !sidecar.is_null() {
        drop(Box::from_raw(sidecar));
    }
}

#[no_mangle]
pub extern "C" fn hello_world() {
    println!("Hey there from Rust parts of retsnoop!\n");
}
