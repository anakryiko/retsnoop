extern crate addr2line;
extern crate clap;
extern crate fallible_iterator;
extern crate gimli;
extern crate memmap;
extern crate object;
extern crate typed_arena;

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, Lines, StdinLock, Write};
use std::path::Path;

use clap::{App, Arg, ArgMatches, Values};
use fallible_iterator::FallibleIterator;
use object::{Object, ObjectSection, SymbolMap, SymbolMapName};
use typed_arena::Arena;
use glob;

use addr2line::{Context, Location};

enum QueryType {
    Addr(u64),
    CompileUnit(String),
    _NotImplemented,
}

fn parse_query_line(string: &str) -> QueryType {
    if string.starts_with("symbolize ") {
        QueryType::Addr(u64::from_str_radix(&string[10..], 16).expect("Failed to parse address"))
    } else if string.starts_with("query_syms ") {
        QueryType::CompileUnit(string[11..].to_string())
    } else {
        panic!("Failed to parse request")
    }
}

enum Addrs<'a> {
    Args(Values<'a>),
    Stdin(Lines<StdinLock<'a>>),
}

fn conv_linux_src_loc<'a>(path: &'a str) -> &'a str {
    let linux_dirs = [
	"arch/", "kernel/", "include/", "block/", "fs/", "net/",
	"drivers/", "mm/", "ipc/", "security/", "lib/", "crypto/",
	"certs/", "init/", "lib/", "scripts/", "sound/", "tools/",
	"usr/", "virt/",
    ];

    for cur_dir in linux_dirs {
        match path.find(cur_dir) {
            Some(pos) => return &path[pos..],
            _ => ()
        }
    }
    path
}

impl<'a> Iterator for Addrs<'a> {
    type Item = QueryType;

    fn next(&mut self) -> Option<QueryType> {
        let text = match *self {
            Addrs::Args(ref mut vals) => vals.next().map(Cow::from),
            Addrs::Stdin(ref mut lines) => lines.next().map(Result::unwrap).map(Cow::from),
        };
        text.as_ref().map(Cow::as_ref).map(parse_query_line)
    }
}

struct Config {
    do_functions: bool,
    do_inlines: bool,
    pretty: bool,
    print_addrs: bool,
    basenames: bool,
    demangle: bool,
    llvm: bool,
}

impl Config {
    fn load(matches: &ArgMatches) -> Config {
        Config {
            do_functions: matches.is_present("functions"),
            do_inlines: matches.is_present("inlines"),
            pretty: matches.is_present("pretty"),
            print_addrs: matches.is_present("addresses"),
            basenames: matches.is_present("basenames"),
            demangle: matches.is_present("demangle"),
            llvm: matches.is_present("llvm"),
        }
    }
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

fn query_address<T: gimli::Endianity>(
    addr: u64,
    ctx: &Context<gimli::EndianSlice<T>>,
    symbols: &SymbolMap<SymbolMapName>,
    config: &Config,
) {
    let probe = addr;

    if config.print_addrs {
        if config.llvm {
            print!("0x{:x}", probe);
        } else {
            print!("0x{:016x}", probe);
        }
        if config.pretty {
            print!(": ");
        } else {
            println!();
        }
    }

    if config.do_functions || config.do_inlines {
        let mut printed_anything = false;
        let mut frames = ctx.find_frames(probe).unwrap().enumerate();
        while let Some((i, frame)) = frames.next().unwrap() {
            if config.pretty && i != 0 {
                print!(" (inlined by) ");
            }

            if config.do_functions {
                if let Some(func) = frame.function {
                    print_function(&func.raw_name().unwrap(), func.language, config.demangle);
                } else if let Some(name) = symbols.get(probe).map(|x| x.name()) {
                    print_function(name, None, config.demangle);
                } else {
                    print!("??");
                }

                if config.pretty {
                    print!(" at ");
                } else {
                    println!();
                }
            }

            print_loc(&frame.location, config.basenames, config.llvm);

            printed_anything = true;

            if !config.do_inlines {
                break;
            }
        }

        if !printed_anything {
            if config.do_functions {
                if let Some(name) = symbols.get(probe).map(|x| x.name()) {
                    print_function(name, None, config.demangle);
                } else {
                    print!("??");
                }

                if config.pretty {
                    print!(" at ");
                } else {
                    println!();
                }
            }

            if config.llvm {
                println!("??:0:0");
            } else {
                println!("??:?");
            }
        }
    } else {
        let loc = ctx.find_location(probe).unwrap();
        print_loc(&loc, config.basenames, config.llvm);
    }

    if config.llvm {
        println!();
    }
    std::io::stdout().flush().unwrap();
}

// List functions defined in compile unit(s) with vi sense.  For every
// compile unit, it starts with a ':e <filename>' line following by
// symbol lines that looks like ' <sym> <address>'.  Show a ':q' line
// after all compile units as the last line of the query result.
//
// For example,
// :e bpf.c
//  bpf_prog_bind_map 0x127b0
//  bpf_enable_stats 0x126a0
//  bpf_task_fd_query 0x125a0
//  ...
// :q
//
fn query_compile_unit<T: gimli::Endianity>(
    compile_unit: &str,
    ctx: &Context<gimli::EndianSlice<T>>,
    _config: &Config,
) {
    let cu_pattern = glob::Pattern::new(compile_unit).unwrap();
    let dwarf = ctx.dwarf();
    let mut units = dwarf.units();
    while let Some(header) = units.next().expect("fail to parse units") {
        let unit = dwarf.unit(header).expect("fail to parse header");
        if unit.name.is_none() {
            continue;
        }
        let name = unit.name.unwrap();
        let name = name.to_string().expect("name of a compile unit");
        if !cu_pattern.matches(conv_linux_src_loc(name)) {
            continue;
        }

        println!(":e {}", name);
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().expect("fail to parse entries") {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }

            let declattr = entry
                .attr(gimli::DW_AT_declaration)
                .expect("DW_AT_declaration");
            if let Some(_) = declattr {
                continue;
            }

            let inlineattr = entry.attr(gimli::DW_AT_inline).expect("DW_AT_inline");
            if let Some(_) = inlineattr {
                continue;
            }

            let func_name_attr = entry
                .attr(gimli::DW_AT_name)
                .expect("no function name attr");
            if func_name_attr.is_none() {
                continue;
            }
            let func_name_attr = func_name_attr.unwrap();

            let low_pc_attr = entry.attr(gimli::DW_AT_low_pc).expect("no low PC");
            let low_pc: u64 = match low_pc_attr {
                Some(low_pc) => {
                    if let gimli::read::AttributeValue::Addr(addr) = low_pc.value() {
                        addr
                    } else {
                        0
                    }
                }
                _ => 0,
            };

            let namestr = func_name_attr
                .string_value(&dwarf.debug_str)
                .unwrap()
                .to_string()
                .expect("should have a string");
            println!(" {} 0x{:x}", namestr, low_pc);
        }
    }
    println!(":q");
    std::io::stdout().flush().unwrap();
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

fn main() {
    let matches = App::new("hardliner")
        .version("0.1")
        .about("A fast addr2line clone")
        .arg(
            Arg::with_name("exe")
                .short("e")
                .long("exe")
                .value_name("filename")
                .help(
                    "Specify the name of the executable for which addresses should be translated.",
                )
                .required(true),
        )
        .arg(
            Arg::with_name("sup")
                .long("sup")
                .value_name("filename")
                .help("Path to supplementary object file."),
        )
        .arg(
            Arg::with_name("functions")
                .short("f")
                .long("functions")
                .help("Display function names as well as file and line number information."),
        )
        .arg(
            Arg::with_name("pretty")
                .short("p")
                .long("pretty-print")
                .help(
                    "Make the output more human friendly: each location are printed on \
                     one line.",
                ),
        )
        .arg(Arg::with_name("inlines").short("i").long("inlines").help(
            "If the address belongs to a function that was inlined, the source \
             information for all enclosing scopes back to the first non-inlined \
             function will also be printed.",
        ))
        .arg(
            Arg::with_name("addresses")
                .short("a")
                .long("addresses")
                .help(
                    "Display the address before the function name, file and line \
                     number information.",
                ),
        )
        .arg(
            Arg::with_name("basenames")
                .short("s")
                .long("basenames")
                .help("Display only the base of each file name."),
        )
        .arg(Arg::with_name("demangle").short("C").long("demangle").help(
            "Demangle function names. \
             Specifying a specific demangling style (like GNU addr2line) \
             is not supported. (TODO)",
        ))
        .arg(
            Arg::with_name("llvm")
                .long("llvm")
                .help("Display output in the same format as llvm-symbolizer."),
        )
        .arg(
            Arg::with_name("addrs")
                .takes_value(true)
                .multiple(true)
                .help("Addresses to use instead of reading from stdin."),
        )
        .get_matches();

    let arena_data = Arena::new();

    let config = Config::load(&matches);
    let path = matches.value_of("exe").unwrap();

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

    let sup_map;
    let sup_object = if let Some(sup_path) = matches.value_of("sup") {
        let sup_file = File::open(sup_path).unwrap();
        sup_map = unsafe { memmap::Mmap::map(&sup_file).unwrap() };
        Some(object::File::parse(&*sup_map).unwrap())
    } else {
        None
    };

    let symbols = object.symbol_map();
    let mut dwarf = gimli::Dwarf::load(&mut load_section).unwrap();
    if let Some(ref sup_object) = sup_object {
        let mut load_sup_section = |id: gimli::SectionId| -> Result<_, _> {
            load_file_section(id, sup_object, endian, &arena_data)
        };
        dwarf.load_sup(&mut load_sup_section).unwrap();
    }

    let ctx = Context::from_dwarf(dwarf).unwrap();

    let stdin = std::io::stdin();
    let queries = matches
        .values_of("addrs")
        .map(Addrs::Args)
        .unwrap_or_else(|| Addrs::Stdin(stdin.lock().lines()));

    for addr_or_cunit in queries {
        match addr_or_cunit {
            QueryType::Addr(probe) => query_address(probe, &ctx, &symbols, &config),
            QueryType::CompileUnit(compile_unit) => {
                query_compile_unit(&compile_unit, &ctx, &config)
            }
            _ => panic!("not implemented yet"),
        }
    }
}
