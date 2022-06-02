import pefile
from iced_x86 import *

IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xf0000000;
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 0x1c;

def resolve_file_address(pe_object,virtual_address):
    base = pe_object.OPTIONAL_HEADER.ImageBase
    header_size = pe_object.NT_HEADERS.OPTIONAL_HEADER.SizeOfHeaders
    size_count = header_size
    
    for section in pe_object.sections:
        if(virtual_address >= base + section.VirtualAddress and virtual_address < base + section.VirtualAddress+section.SizeOfRawData):
            return (size_count + (virtual_address - (base + section.VirtualAddress)), section.Name.decode('utf-8').rstrip('\x00'))
        else:
            size_count+=section.SizeOfRawData
    
    return

def get_imports(pe_object):
    imports = {}
    try:
        for entry in pe_object.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                if dll_name in imports:
                    imports[dll_name].append(imp)
                else:
                    imports[dll_name] = [imp]
    except AttributeError:
        print("[x] Error: No DIRECTORY_ENTRY_IMPORT")
    return imports

def get_exports(pe_object):
    exports = []
    try:
        for entry in pe_object.DIRECTORY_ENTRY_EXPORT.symbols:
            #print(hex(pe_object.OPTIONAL_HEADER.ImageBase + entry.address), entry.name, entry.ordinal)
            exports.append(entry)
    except AttributeError:
        print("[x] Error: No DIRECTORY_ENTRY_EXPORT")
    return exports

def get_exception_table_functions(pe_object):
    functions = []
    try:
        for entry in pe_object.DIRECTORY_ENTRY_EXCEPTION:
            #print(hex(pe_object.OPTIONAL_HEADER.ImageBase + entry.address), entry.name, entry.ordinal)
            functions.append(pe_object.OPTIONAL_HEADER.ImageBase + entry.struct.BeginAddress)

    except AttributeError:
        print("[x] Error: No DIRECTORY_ENTRY_EXCEPTION")
    return functions

#if va_format = True the table is filled with virtual address, if False, is filled with the file address
def get_cfg_table(pe_object, pe_file, va_format = True):
    cfg_table = []
    
    try:
        cgf_lags = pe_object.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags
        padding_size = (cgf_lags &
			IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
        cfg_entry_size = padding_size + 4
        cfg_table_size = pe_object.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount * cfg_entry_size
        cfg_table_file_addr = resolve_file_address(pe_object, pe_object.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable)[0]
        cfg_table_bytes = read_from_offset(pe_file, cfg_table_file_addr, cfg_table_size)

        for function_count in range(0, pe_object.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount):
            base = pe_object.OPTIONAL_HEADER.ImageBase
            entry_offset = function_count * cfg_entry_size
            addr = base + int.from_bytes(cfg_table_bytes[entry_offset : entry_offset+4], "little")
            if not va_format:
                addr = resolve_file_address(pe_object, addr)[0]
            cfg_table.append(addr)
    except AttributeError:
        print("[x] Error: No DIRECTORY_ENTRY_LOAD_CONFIG")
    return cfg_table

def filter_functions(pe_object, function_list):
    function_list.sort()
    new_function_list = []
    for function_addr in function_list:
        if not resolve_file_address(pe_object, function_addr):
            print("[x] Error: Found function out of bound: %s" % hex(function_addr))
        if resolve_file_address(pe_object, function_addr)[1] != '.text':
            break
        new_function_list.append(function_addr)
    
    return new_function_list

def get_function_addresses(pe_object, pe_file):
    functions = get_cfg_table(pe_object, pe_file)
    for addr in get_exception_table_functions(pe_object):
        if addr not in functions:
            functions.append(addr)

    for entry in get_exports(pe_object):
        addr = pe_object.OPTIONAL_HEADER.ImageBase + entry.address
        if addr not in functions:
            functions.append(addr)

    return filter_functions(pe_object, functions)

def get_named_address_function_list(pe_object):
    functions = {}
    imports = get_imports(pe_object)
    for key, value in imports.items():
        for import_function in value:
            if not import_function.name:
                functions[import_function.address] = key + '!Ordinal_' + str(import_function.ordinal)
                continue
            functions[import_function.address] = key + '!' + import_function.name.decode('utf-8')
    
    exports = get_exports(pe_object)
    for exported_function in exports:
        if not exported_function.name:
                functions[pe_object.OPTIONAL_HEADER.ImageBase + exported_function.address] = 'local!' + str(exported_function.ordinal)
                continue
        functions[pe_object.OPTIONAL_HEADER.ImageBase + exported_function.address] = 'local!' + exported_function.name.decode('utf-8')

    functions[pe_object.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Reserved2] = 'local!GuardCFDispatcherFunction'

    return functions

def get_funct_address(pe_object,function_name):
    imports = get_imports(pe_object)
    for imported_functions in imports.values():
        for entry in imported_functions:
            if function_name in entry.name.decode('utf-8'):
                return entry.address
    
    exports = get_exports(pe_object)
    for entry in exports:
        if function_name in entry.name.decode('utf-8'):
            return pe_object.OPTIONAL_HEADER.ImageBase + entry.address

def read_from_offset(file, offset, size):
    file.seek(offset, 0)
    return file.read(size)

def dissasemble_function(pe_object, pe_file, virtual_addr, size):
    file_addr = resolve_file_address(pe_object, virtual_addr)[0]
    function_content = read_from_offset(pe_file, file_addr, size)
    ip = virtual_addr
    decoder = Decoder(64, function_content, ip = ip)
    formatter = Formatter(FormatterSyntax.NASM)
    for instr in decoder:
        #disasm = formatter.format(instr)
        mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        operands_str = formatter.format_all_operands(instr)
        if mnemonic_str != 'int3':
            print(mnemonic_str, '\t', operands_str)

def get_operand_address(operands_str):
    if '[' in operands_str and ']' in operands_str:
        rel_content = operands_str[operands_str.index('[') + 1:operands_str.index(']')]
        for val in rel_content.split(" "):
            if val.endswith('h') and '+' not in val:
                return int(val.rstrip('h'), 16)
    else:
        if operands_str.endswith('h') and '+' not in operands_str:
            addr_operand = operands_str.split(" ")[-1]
            return int(addr_operand.rstrip('h'), 16)
    raise Exception("[x] Error: Couldnt parse operand: %s" % operands_str)

def get_calls(pe_object, pe_file, virtual_addr, size):
    file_addr = resolve_file_address(pe_object, virtual_addr)[0]
    function_content = read_from_offset(pe_file, file_addr, size)
    ip = virtual_addr
    decoder = Decoder(64, function_content, ip = ip)
    formatter = Formatter(FormatterSyntax.NASM)

    call_list = []
    #print("Function at:", hex(virtual_addr))
    for instr in decoder:
        mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        operands_str = formatter.format_all_operands(instr)
        #print(mnemonic_str, operands_str)
        if mnemonic_str == 'call':
            try:
                operand_addr = get_operand_address(operands_str)
                if not resolve_file_address(pe_object, operand_addr):
                    raise Exception("[x] Error: Address out of bounds")
                    
                call_list.append(get_operand_address(operands_str))
            except Exception as e:
                print("[x] Error: Couldnt parse operand at: ", hex(virtual_addr))
                print(str(e))
    
    return call_list

def is_instruction_jump(pe_object, pe_file, virtual_address):
    file_addr = resolve_file_address(pe_object,virtual_address)
    if file_addr[1] != '.text':
        return False
    inst_bytes = read_from_offset(pe_file, file_addr[0], 6)
    decoder = Decoder(64, inst_bytes, ip = virtual_address)
    formatter = Formatter(FormatterSyntax.NASM)
    instr = decoder.decode()
    mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
    operands_str = formatter.format_all_operands(instr)
    if mnemonic_str != 'jmp':
        return False
    
    return get_operand_address(operands_str)


#Call can go to: 
#   if in .text:
#       1. thunked function (jmp) then to 3
#       2. local function
#   if not in .text
#       3. imported function
#
#   At the moment it doesnt resolve dalay loaded modules
def resolve_call_name(pe_object, pe_file, indexable_function_table, virtual_address):
    call_file_addr = resolve_file_address(pe_object,virtual_address)
    
    if call_file_addr[1] == '.didat':
        return 'local!DelayedDllFunction_' + hex(virtual_address)

    if call_file_addr[1] != '.text':
        if virtual_address not in indexable_function_table.keys():
            addr = int.from_bytes(read_from_offset(pe_file, call_file_addr[0], 8), 'little')
            if addr not in indexable_function_table.keys():
                return "local!Function_" + hex(addr)

            return indexable_function_table[addr]
        
        return indexable_function_table[virtual_address]
    
    is_jmp = is_instruction_jump(pe_object,pe_file,virtual_address)
    if not is_jmp:
        if virtual_address not in indexable_function_table.keys():
            return "local!Function_" + hex(virtual_address)

        return indexable_function_table[virtual_address]

    return resolve_call_name(pe_object, pe_file, indexable_function_table, is_jmp)

def get_named_calls_by_cfg_index(pe_object, pe_file, indexable_function_table, function_addr_list, list_index):
    #print("Parsing function from: %s to %s" % (hex(function_addr_list[list_index]), hex(function_addr_list[list_index+1])))
    call_list = get_calls(pe_object, pe_file, function_addr_list[list_index], function_addr_list[list_index+1] - function_addr_list[list_index])

    call_names = []
    for call in call_list:
        call_names.append(resolve_call_name(pe_object, pe_file, indexable_function_table, call))

    return call_names

def get_named_calls_by_function_address(pe_object, pe_file, indexable_function_table, function_addr_list, address):
    cfg_entry = function_addr_list.index(address)
    return get_named_calls_by_cfg_index(pe_object, pe_file, indexable_function_table, function_addr_list, cfg_entry)


def get_named_calls_by_function_name(pe_object, pe_file, indexable_function_table, function_addr_list, function_name):
    addr = get_funct_address(pe_object,function_name)
    return get_named_calls_by_function_address(pe_object, pe_file, indexable_function_table, function_addr_list, addr)

#last function is not analized
def get_all_function_calls(dll_path):
    calls = {}
    file_path = dll_path
    
    pe =  pefile.PE(file_path)
    pe_file = open(file_path, "rb")
    pe.parse_data_directories()

    function_addr_list = get_function_addresses(pe, pe_file)

    if not function_addr_list:
        print("[x] Error: Couldnt find functions")
        return calls

    indexable_function_table = get_named_address_function_list(pe)
    for entry in range(0,len(function_addr_list)-1):
        #try:
        list = get_named_calls_by_cfg_index(pe, pe_file, indexable_function_table, function_addr_list, entry)
        if function_addr_list[entry] in indexable_function_table.keys():
            calls[indexable_function_table[function_addr_list[entry]]] = list
            continue

        calls['local!Function_' + hex(function_addr_list[entry])] = list
        #except Exception as e: # work on python 3.x
        #    print("[x] Error in function at: ", hex(function_addr_list[entry]))
        #    print(str(e))

    return calls

if __name__ == '__main__':
    file_path = 'kernel32.dll'
    function_address = 0x1800a59da
    
    pe =  pefile.PE(file_path)
    pe_file = open(file_path, "rb")
    pe.parse_data_directories()
    function_addr_list = get_function_addresses(pe, pe_file)
    print("whut", function_addr_list)
    if function_addr_list:
        indexable_function_table = get_named_address_function_list(pe)
        print('[+] Finding calls by:', hex(function_address))
        call_names = get_named_calls_by_function_address(pe, pe_file, indexable_function_table, function_addr_list, function_address)

        for call in call_names:
            print('\t[-] Call to:', call)
    else:
        print('[x] ERROR: No functions found')
