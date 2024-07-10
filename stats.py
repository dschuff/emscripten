#!/usr/bin/env python3

from collections import namedtuple
import sys
from tools import extract_metadata, webassembly

VERBOSE = False


def get_direct(module):
    functions = module.get_function_types()
    segments = module.get_elem_segments()
    print(f'{len(functions)} functions, {len(segments)} segments, {segments[0].count} elems')
    names = module.get_names()
    print(f'{len(names)} names')
    return functions, segments, names


def elem_stats(functions: dict[str, webassembly.FuncType], segments, names):
    # Are there duplicates?
    segment = segments[0]
    seen_elems = set()
    duplicates = 0
    for elem in segment.elems:
        name = names.get(elem, '<none>')
        if VERBOSE:
            print(f'elem {elem}: {name}')
        if elem in seen_elems:
            print(f'Duplicate: {elem}: {name}')
            duplicates += 1
        seen_elems.add(elem)
    print(f'Duplicates: {duplicates}')


    # Find functions not in the table
    missing = 0
    for func in range(len(functions)):
        if func not in seen_elems:
            name = names.get(func, '<none>')
            #name = names[func] or '<none>'
            print(f'Not in table: {func}: {name}')
            missing += 1
    print(f'Missing: {missing}')


def get_symtab(module):
    symtab = module.get_symtab()
    print(f'{len(symtab)} symbols')
    for i, sym in enumerate(symtab):
        if VERBOSE:
            print(f'sym {i}: {sym}')
    return symtab


def get_relocs(module):
    code_relocs = module.get_relocs('CODE')
    data_relocs = module.get_relocs('DATA')
    print(f'{len(code_relocs)} code relocs')
    print(f'{len(data_relocs)} data relocs')


class CodeMap:
    def __init__(self, module):
        self.function_bodies = module.get_functions()
        self.code_sec_offset = module.get_section(webassembly.SecType.CODE).offset
        self.num_imported_funcs = module.num_imported_funcs()

        last = self.function_bodies[0].offset - 1
        for i, func in enumerate(self.function_bodies):
            assert func.offset >= last + 1, f'offset mismatch: {func.offset} {last}'
            last = func.offset + func.size
            if VERBOSE:
                print(f'func body fnidx {i + self.num_imported_funcs} @{func.offset} ({func.size})')

    def search(self, addr) -> int:
        addr += self.code_sec_offset

        def isearch(start, end):
            i = (end + start) // 2
            if addr >= self.function_bodies[i].offset + self.function_bodies[i].size:
                if start == len(self.function_bodies):
                    raise Exception(f'addr {addr} too large')
                return isearch(i + 1, end)
            elif addr < self.function_bodies[i].offset:
                if end == 0:
                    raise Exception(f'addr {addr} too small')
                return isearch(start, i)
            else:
                return i
        result = isearch(0, len(self.function_bodies))
        body = self.function_bodies[result]
        assert addr >= body.offset and addr < body.offset + body.size
        return result + self.num_imported_funcs


class DataMapSymtab:
    def __init__(self, module, datamap):
        self.addrsegments = []
        Segment = namedtuple('Segment', ['address', 'size', 'orig_index'])
        symtab = module.get_symtab()
        last = 0
        for i, sym in enumerate(symtab):
            if sym.kind != webassembly.SymbolKind.DATA:
                continue
            address = datamap.addresses[sym.index] + sym.offset
            self.addrsegments.append(Segment(address, sym.size, i))
        self.addrsegments.sort(key=lambda x: x.address)
        for i, sym in enumerate(self.addrsegments):
            if VERBOSE:
                print(f'datasym {i}({sym.orig_index}) @{sym.address}-{sym.address + sym.size} ({sym.size})')
                if sym.address > last:
                    print(f' gap: {sym.address - last - 1}')
            #assert sym.address >= last, f'offset mismatch: {sym.address} {last}'
            if sym.address < last:
                last_sym = self.addrsegments[i-1]
                kind = 'partial'
                if last_sym.address == sym.address and last_sym.size == sym.size:
                    kind = 'full'
                elif last_sym.address + last_sym.size == sym.address + sym.size:
                    kind = 'suffix'
                elif last_sym.address == sym.address:
                    kind = 'prefix'
                elif sym.size == 0:
                    kind = 'zero'
                print(f'symbol overlap: {kind}')
            last = sym.address + sym.size
    
    def search(self, addr) -> int:
        def isearch(start, end):
            i = (end + start) // 2
            if addr >= self.addrsegments[i].address + self.addrsegments[i].size:
                if start == len(self.addrsegments):
                    raise Exception('addr too large')
                return isearch(i + 1, end)
            elif addr < self.addrsegments[i].address:
                if end == 0:
                    raise Exception('addr too small')
                return isearch(start, i)
            else:
                return i
        result = isearch(0, len(self.addrsegments))
        return self.addrsegments[result].orig_index


class DataMap:
    def __init__(self, module):
        self.data_segments = module.get_segments()
        self.addresses = []
        
        for seg in self.data_segments:
            offset = None
            if seg.init:
                offset = extract_metadata.to_unsigned(extract_metadata.get_const_expr_value(seg.init))
                self.addresses.append(offset)
            else:
                passive_offset_map = extract_metadata.get_passive_segment_offsets(module)
                self.addresses.append(passive_offset_map[seg])
        assert len(self.addresses) == len(self.data_segments)

        last = self.addresses[0] - 1
        for idx, address in enumerate(self.addresses):
            assert address >= last, f'offset mismatch: {address} {last}'
            seg = self.data_segments[idx]
            
            if VERBOSE:
                print(f'dataseg {idx} @{address}-{address + seg.size} ({seg.size})')
                if address > last + 1:
                    print(f' gap: {address - last - 1}')
            last = address + seg.size

    def search(self, addr) -> int:

        def isearch(start, end):
            i = (end + start) // 2
            if addr >= self.addresses[i] + self.data_segments[i].size:
                if start == len(self.addresses):
                    raise Exception(f'addr {addr} too large')
                return isearch(i + 1, end)
            elif addr < self.addresses[i]:
                if end == 0:
                    raise Exception(f'addr {addr} too small, at {i}, {self.data_segments[i]}')
                return isearch(start, i)
            else:
                return i
        result = isearch(0, len(self.data_segments))
        segment = self.data_segments[result]
        assert addr >= self.addresses[result] and addr < self.addresses[result] + segment.size
        return result


class Symtab:
    def __init__(self, module):
        self.symtab = module.get_symtab()
        self.name_map = {}
        for sym in self.symtab:
            self.name_map[sym.name] = sym

    def sym_by_name(self, name: str) -> webassembly.SymInfo:
        return self.name_map.get(name)
        return None
        raise Exception(f'symbol {name} not found')


class CallgraphNode:
    def __init__(self, kind: webassembly.SymbolKind, index: int, name: str):
        self.kind = kind
        self.index = index
        self.direct_edges = set()
        self.indirect_edges = set()
        self.name = name

    def add_edge(self, node):
        self.direct_edges.add(node)

    def add_indirect_edge(self, node):
        self.indirect_edges.add(node)


class Callgraph:
    def __init__(self, module):
        self.nodes = {}

    def get(self, kind: webassembly.SymbolKind, index: int, name: str):
        return self.nodes.get((kind, index), CallgraphNode(kind, index, name))


def symtab_stats(module):
    names = module.get_names()
    symtab = get_symtab(module)
    Tab = Symtab(module)
    code_relocs = module.get_relocs('CODE')
    data_relocs = module.get_relocs('DATA')
    func_map = CodeMap(module)
    data_map = DataMap(module)
    dms = DataMapSymtab(module, data_map)
    callgraph = Callgraph(module)
    
    for reloc in code_relocs:
        if VERBOSE:
            print(f'CODE reloc off {reloc.offset} idx {reloc.index} type {webassembly.RelocType(reloc.reloc_type).name} sym {symtab[reloc.index]}')
        if reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB and reloc.reloc_type != webassembly.RelocType.GLOBAL_INDEX_LEB:
            source: int = func_map.search(reloc.offset)
            fname = names[source]
            ssym = Tab.sym_by_name(fname)
            if VERBOSE:
                print(f'source function {source} fname {fname} sym {ssym}')
                print(f' to symbol {symtab[reloc.index]}')
            if ssym and ssym.flags & webassembly.SymbolFlags.BINDING_LOCAL == 0:
                assert ssym.index == source, f'source {source} sym {ssym}'
            dsym = symtab[reloc.index]
            print(f'{fname} (F) -> {dsym.name} ({webassembly.SymbolKind(dsym.kind).name})')
            snode = callgraph.get(webassembly.SymbolKind.FUNCTION, source, fname)
            dnode = callgraph.get(dsym.kind, dsym.index, dsym.name)
            if 'TABLE_INDEX' in reloc.reloc_type.name:
                snode.add_indirect_edge(dnode)
            else:
                snode.add_edge(dnode)
            # TODO check that reloc type matches type of symbol
                 
    for reloc in data_relocs:
        print(f'DATA reloc off {reloc.offset} idx {reloc.index} name {symtab[reloc.index]}')
        assert reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB
        data_section = module.get_section(webassembly.SecType.DATA)
        if reloc.offset > data_section.size:
            print(f'  reloc offset {reloc.offset} > data section size {data_section.size}')
            sys.exit(1)
        #source = data_map.search(reloc.offset)
        continue
        source = dms.search(reloc.offset)
        print(source)
        name = symtab[source].name
        snode = callgraph.get(webassembly.SymbolKind.DATA, source, name)
        dsym = symtab[reloc.index]
        dnode = callgraph.get(dsym.kind, dsym.index, dsym.name)
        if 'TABLE_INDEX' in reloc.reloc_type.name:
            snode.add_indirect_edge(dnode)
        else:
            snode.add_edge(dnode)
        print(f'{snode.name} (D) -> {dsym.name} ({webassembly.SymbolKind(dsym.kind).name})')
        

def check_names(module):
    '''Check that symbol table names match name section names'''
    names = module.get_names()
    symtab = module.get_symtab()
    for sym in symtab:
        if sym.kind != webassembly.SymbolKind.FUNCTION:
            continue
        if sym.name != names[sym.index]:
            def san(s):
                return s.replace('C1', '##').replace('C2', '##').replace('D1', '##').replace('D2', '##')
            # There are a bunch of symbols that from eyeballing seem to be the result of some kind of deduping or aliasing
            if san(sym.name) != san(names[sym.index]):
                print(f'name mismatch: Sym {sym.name} func index {sym.index} name {names[sym.index]}')


def main(argv):
    with webassembly.Module(argv[1]) as module:
        functions, segments, names = get_direct(module)
        #elem_stats(functions, segments, names)
        check_names(module)
        symtab_stats(module)


if __name__ == '__main__':
    if '-v' in sys.argv:
        VERBOSE = True
    if '-p' in sys.argv:
        import cProfile
        with cProfile.Profile() as pr:
            main(sys.argv)
        pr.print_stats()
    else:
        main(sys.argv)

