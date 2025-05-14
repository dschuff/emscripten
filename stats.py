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
            if VERBOSE:
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


def check_data_syms(module, datamap):
    symsegments = []
    # Offset is from the symbol table (offset into the data section)
    SymbolSegment = namedtuple('SymbolSegment', ['offset', 'size', 'symtab_index'])
    symtab = module.get_symtab()
    last = 0
    for i, sym in enumerate(symtab):
        if sym.kind != webassembly.SymbolKind.DATA or sym.flags & webassembly.SymbolFlags.SYM_UNDEFINED:
            continue
        global_offset = datamap.datasec_offsets[sym.index] + sym.offset
        symsegments.append(SymbolSegment(global_offset, sym.size, i))
    symsegments.sort(key=lambda x: x.offset)
    for i, sym in enumerate(symsegments):
        if VERBOSE:
            print(f'datasym {i}({sym.symtab_index}) @{sym.offset}-{sym.offset + sym.size} ({sym.size}b)')
            if sym.offset > last:
                print(f' gap: {sym.offset - last - 1}')
        #assert sym.address >= last, f'offset mismatch: {sym.address} {last}'
        if sym.offset < last:
            last_sym = symsegments[i-1]
            kind = 'partial!'
            if last_sym.offset == sym.offset and last_sym.size == sym.size:
                kind = 'full'
            elif last_sym.offset + last_sym.size == sym.offset + sym.size:
                kind = 'suffix'
            elif last_sym.offset == sym.offset:
                kind = 'prefix'
            elif sym.size == 0:
                kind = 'zero'
            if VERBOSE or kind == 'partial!':
                print(f'symbol overlap: {kind}')
        last = sym.offset + sym.size


def segment_from_symbol(module, symindex):
    symtab = module.get_symtab()
    sym = symtab[symindex]
    assert sym.kind == webassembly.SymbolKind.DATA
    assert sym.index is not None
    return sym.index


class Symtab:
    def __init__(self, module):
        self.symtab = module.get_symtab()
        self.name_map = {}
        self.function_syms = {}
        self.data_syms = {}
        for sym in self.symtab:
            if sym.flags & (webassembly.SymbolFlags.SYM_ABSOLUTE | webassembly.SymbolFlags.SYM_UNDEFINED):
                continue
            self.name_map[sym.name] = sym
            if sym.kind == webassembly.SymbolKind.FUNCTION:
                self.function_syms[sym.index] = sym
            elif sym.kind == webassembly.SymbolKind.DATA:
                self.data_syms[sym.index] = sym
        return
        data_segments = module.get_segments()
        self.datasec_offsets = []
        self.segment_offsets = [seg.offset for seg in data_segments]
        for sym in self.data_syms:
            sym_addr = data_segments[sym.index].offset + sym.offset

    def sym_by_name(self, name: str) -> webassembly.SymInfo:
        return self.name_map.get(name)
        return None
        raise Exception(f'symbol {name} not found')

    def sym_by_module_index(self, kind, index):
        if kind == webassembly.SymbolKind.FUNCTION:
            return self.function_syms[index]
        elif kind == webassembly.SymbolKind.DATA:
            return self.data_syms[index]
        raise Exception(f'bad symbol kind: {webassembly.SymbolKind(kind).name}')


class DataMap:
    def __init__(self, module):
        self.data_segments = module.get_segments()
        self.data_sec_file_offset = module.get_section(webassembly.SecType.DATA).offset
        self.datasec_offsets = []
        self.datasec_offsets = [seg.offset - self.data_sec_file_offset for seg in self.data_segments]

        last = self.datasec_offsets[0] - 1
        for idx, offset in enumerate(self.datasec_offsets):
            assert offset >= last, f'offset mismatch: {offset} {last}'
            seg = self.data_segments[idx]
            
            if VERBOSE:
                print(f'dataseg {idx} @{offset}-{offset + seg.size} ({seg.size})')
                if offset > last + 1:
                    print(f' gap: {offset - last - 1}')
            last = offset + seg.size

    def search(self, addr) -> int:

        def isearch(start, end):
            i = (end + start) // 2
            if addr >= self.datasec_offsets[i] + self.data_segments[i].size:
                if start == len(self.datasec_offsets):
                    raise Exception(f'addr {addr} too large')
                return isearch(i + 1, end)
            elif addr < self.datasec_offsets[i]:
                if end == 0:
                    raise Exception(f'addr {addr} too small, at {i}, {self.data_segments[i]}')
                return isearch(start, i)
            else:
                return i
        result = isearch(0, len(self.data_segments))
        segment = self.data_segments[result]
        assert addr >= self.datasec_offsets[result] and addr < self.datasec_offsets[result] + segment.size
        return result

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

    def __repr__(self):
        return self.name


class Callgraph:
    def __init__(self, module):
        self.nodes = {}
        self.nodes_by_name = {}

    def get(self, kind: webassembly.SymbolKind, index: int, name: str):
        return self.nodes.setdefault((kind, index), CallgraphNode(kind, index, name))

    def get_existing_func(self, index):
        return self.nodes[(webassembly.SymbolKind.FUNCTION, index)]

    def index_nodes(self):
        if len(self.nodes_by_name):
            return
        for node in self.nodes.values():
            l = self.nodes_by_name.setdefault(node.name, [])
            l.append(node)

    def get_reachable_from_funcs(self, symnames):
        self.index_nodes()
        seen_nodes = set()
        for n in symnames:
            nodes = [x for x in self.nodes_by_name[n] if x.kind == webassembly.SymbolKind.FUNCTION]
            if not nodes:
                raise Exception(f'No function nodes found for {n}')
            if len(nodes) > 1:
                raise Exception(f'Multiple function nodes found for {n}')
            seen_nodes.add(nodes[0])
        worklist = list(seen_nodes)
        while worklist:
            cur = worklist.pop()
            for edge in cur.direct_edges:
                if edge not in seen_nodes:
                    seen_nodes.add(edge)
                    worklist.append(edge)
            # now do the indirect edges
            for edge in cur.indirect_edges:
                if edge not in seen_nodes:
                    seen_nodes.add(edge)
                    worklist.append(edge)
        return seen_nodes




def symtab_stats(module):
    names = module.get_names()
    symtab = get_symtab(module)
    Tab = Symtab(module)
    code_relocs = module.get_relocs('CODE')
    data_relocs = module.get_relocs('DATA')
    func_map = CodeMap(module)
    data_map = DataMap(module)
    check_data_syms(module, data_map)
    callgraph = Callgraph(module)
    
    for reloc in code_relocs:
        if VERBOSE:
            print(f'CODE reloc off {reloc.offset} idx {reloc.index} type {webassembly.RelocType(reloc.reloc_type).name} sym {symtab[reloc.index]}')
        if reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB and reloc.reloc_type != webassembly.RelocType.GLOBAL_INDEX_LEB:
            source: int = func_map.search(reloc.offset)
            #fname = names[source]
            ssym = Tab.sym_by_module_index(webassembly.SymbolKind.FUNCTION, source)
            fname = ssym.name
            #ssym = Tab.sym_by_name(fname)
            if VERBOSE:
                print(f' source function {source} fname {fname} sym {ssym}')
                print(f'  to symbol {symtab[reloc.index]}')
            if ssym and ssym.flags & webassembly.SymbolFlags.BINDING_LOCAL == 0:
                assert ssym.index == source, f'source {source} sym {ssym}'
            dsym = symtab[reloc.index]
            print(f'{fname} (F) -> {dsym.name} ({webassembly.SymbolKind(dsym.kind).name}) via {reloc.reloc_type.name}')
            snode = callgraph.get(webassembly.SymbolKind.FUNCTION, source, fname)
            dnode = callgraph.get(dsym.kind, dsym.index, dsym.name)
            if 'TABLE_INDEX' in reloc.reloc_type.name:
                snode.add_indirect_edge(dnode)
            else:
                snode.add_edge(dnode)
            # TODO check that reloc type matches type of symbol
                 
    for reloc in data_relocs:
        if VERBOSE:
            print(f'DATA reloc off {reloc.offset} idx {reloc.index} name {symtab[reloc.index]}')
        assert reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB
        data_section = module.get_section(webassembly.SecType.DATA)
        if reloc.offset > data_section.size:
            print(f'  reloc offset {reloc.offset} > data section size {data_section.size}')
            sys.exit(1)
        source = data_map.search(reloc.offset)
        #source = dms.search(reloc.offset)
        if VERBOSE:
            print(f' source segment {source} sym {ssym}')
            print(f'  to symbol {symtab[reloc.index]}')
        name = Tab.sym_by_module_index(webassembly.SymbolKind.DATA, source).name
        snode = callgraph.get(webassembly.SymbolKind.DATA, source, name)
        dsym = symtab[reloc.index]
        dnode = callgraph.get(dsym.kind, dsym.index, dsym.name)
        if 'TABLE_INDEX' in reloc.reloc_type.name:
            snode.add_indirect_edge(dnode)
        else:
            snode.add_edge(dnode)
        print(f'{snode.name} (D) -> {dsym.name} ({webassembly.SymbolKind(dsym.kind).name}) via {reloc.reloc_type.name}')

    return callgraph

    
def elem_data_stats(module: webassembly.Module, callgraph: Callgraph):
    segments = module.get_elem_segments()
    assert len(segments) == 1
    segment = segments[0]
    symtab = module.get_symtab()
    indirect_reachable_functions = {}
    
    for node in callgraph.nodes.values():
        for dest in node.indirect_edges:
            if dest.kind == webassembly.SymbolKind.FUNCTION:
                count = indirect_reachable_functions.get(dest.name, 0)
                indirect_reachable_functions[dest.name] = count + 1
    total = len(indirect_reachable_functions)
    print(f'{total} indirectly-reachable functions')
    funcs = list(indirect_reachable_functions.keys())
    funcs.sort(key=lambda x:indirect_reachable_functions[x])
    for func in funcs:
        print(f' irf {func} reached by {indirect_reachable_functions[func]}')

    for elem in segment.elems:
        pass 
        # get the callgraph node for the elem
        # report the # of indirect incoming edges

def check_names(module):
    '''Check that symbol table names match name section names'''
    names = module.get_names()
    symtab = module.get_symtab()
    assert len(symtab) > 0
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
        elem_stats(functions, segments, names)
        check_names(module)
        callgraph = symtab_stats(module)
        elem_data_stats(module, callgraph)
        #entry = ['gzread', 'gzopen']
        def setPrint(s):
            print([f.name for f in sorted(s, key=lambda x:x.name)])
        entry = ['foo', 'bar']
        r = callgraph.get_reachable_from_funcs(entry)
        print(f'reachable from {entry}')
        setPrint(r)
        anchor = '_ZN4wasm19OptimizationOptions9runPassesERNS_6ModuleE'
        anchor = 'baz'
        print(f'reachable from {anchor}')
        pr = callgraph.get_reachable_from_funcs([anchor])
        setPrint(pr)
        print('reachable from both (intersection)')
        setPrint(pr & r)
        print('difference')
        setPrint(r - pr)



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

