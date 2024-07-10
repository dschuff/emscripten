#!/usr/bin/env python3

import sys
from tools import webassembly

VERBOSE = False


def get_direct(filename):
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
    for sym in symtab:
        if VERBOSE:
            print(f'sym {sym}')
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
        for func in self.function_bodies:
            assert func.offset >= last + 1, f'offset mismatch: {func.offset} {last}'
            last = func.offset + func.size
            if VERBOSE:
                print(f'func {func.offset} {func.size}')

    def search(self, addr) -> webassembly.FunctionBody:
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


class DataMap:
    def __init__(self, module):
        self.data_segments = module.get_segments()
        
        last = self.data_segments[0].offset - 1
        for seg in self.data_segments:
            assert seg.offset >= last + 1, f'offset mismatch: {seg.offset} {last}'
            last = seg.offset + seg.size
            if VERBOSE:
                print(f'dataseg {seg.offset} {seg.size}')

    def search(self, addr) -> webassembly.DataSegment:

        def isearch(start, end):
            i = (end + start) // 2
            if addr >= self.data_segments[i].offset + self.data_segments[i].size:
                if start == len(self.data_segments):
                    raise Exception(f'addr {addr} too large')
                return isearch(i + 1, end)
            elif addr < self.data_segments[i].offset:
                if end == 0:
                    raise Exception(f'addr {addr} too small, at {i}, {self.data_segments[i]}')
                return isearch(start, i)
            else:
                return i
        result = isearch(0, len(self.data_segments))
        segment = self.data_segments[result]
        assert addr >= segment.offset and addr < segment.offset + segment.size
        return result # + self.num_imported_funcs       


class Symtab:
    def __init__(self, module):
        self.symtab = module.get_symtab()

    def sym_by_name(self, name) -> webassembly.SymInfo:
        for sym in self.symtab:
            if sym.name == name:
                return sym
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

    def get(self, kind, index, name):
        return self.nodes.get((kind, index), CallgraphNode(kind, index, name))


def symtab_stats(module):
    symtab = get_symtab(module)
    Tab = Symtab(module)
    code_relocs = module.get_relocs('CODE')
    data_relocs = module.get_relocs('DATA')
    func_map = CodeMap(module)
    data_map = DataMap(module)
    callgraph = Callgraph(module)
    
    for reloc in code_relocs:
        if VERBOSE:
            print(f'CODE reloc off {reloc.offset} idx {reloc.index} type {webassembly.RelocType(reloc.reloc_type).name} sym {symtab[reloc.index]}')
        if reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB and reloc.reloc_type != webassembly.RelocType.GLOBAL_INDEX_LEB:
            source = func_map.search(reloc.offset)
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
        print(f'DATA reloc idx {reloc.index} name {symtab[reloc.index]}')
        assert reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB
        source = data_map.search(reloc.offset)
        snode = callgraph.get(webassembly.SymbolKind.DATA, source, names[source])
        dsym = symtab[reloc.index]
        dnode = callgraph.get(dsym.ind, dsym.index, dsym.name)
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
        print(sym)
        if sym.kind != webassembly.SymbolKind.FUNCTION:
            continue
        if sym.name != names[sym.index]:
            print(f'name mismatch: Sym {sym.name} index {sym.index} name {names[sym.index]}')


if __name__ == '__main__':
    if '-v' in sys.argv:
        VERBOSE = True
    with webassembly.Module(sys.argv[1]) as module:
        functions, segments, names = get_direct(module)
        elem_stats(functions, segments, names)
        check_names(module)
        symtab_stats(module)
