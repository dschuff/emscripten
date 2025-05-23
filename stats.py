#!/usr/bin/env python3

from collections import namedtuple
import sys
from tools import webassembly

VERBOSE = False

def get_symtab(module):
    symtab = module.get_symtab()
    print(f'{len(symtab)} symbols')
    for i, sym in enumerate(symtab):
        if VERBOSE:
            print(f'sym {i}: {sym}')
    return symtab


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


def check_data_syms(symtab):
    last = 0
    for i, sym in enumerate(symtab.data_syms_list):
        if VERBOSE:
            print(f'datasym {i}({sym.sym_index}) @({sym.datasec_offset}-{sym.datasec_offset + sym.sym.size}) ({sym.sym.size}b)')
            if sym.datasec_offset > last:
                print(f' gap: {sym.datasec_offset - last - 1}')
        #assert sym.address >= last, f'offset mismatch: {sym.address} {last}'
        if sym.datasec_offset < last:
            last_sym = symtab.data_syms_list[i-1]
            kind = 'partial!'
            if last_sym.datasec_offset == sym.datasec_offset and last_sym.sym.size == sym.sym.size:
                kind = 'full'
            elif last_sym.datasec_offset + last_sym.sym.size == sym.datasec_offset + sym.sym.size:
                kind = 'suffix'
            elif last_sym.datasec_offset == sym.datasec_offset:
                kind = 'prefix'
            elif sym.sym.size == 0:
                kind = 'zero'
            if VERBOSE or kind == 'partial!':
                print(f'symbol overlap: {kind}')
        last = sym.datasec_offset + sym.sym.size


class Symtab:
    def __init__(self, module:webassembly.Module):
        self.symtab = module.get_symtab()
        self.name_map: dict[str, webassembly.SymInfo] = {}
        # Function and data symbols indexed by module index (function/segment index)
        # TODO: it's not yet clear whether these are needed
        self.function_syms: dict[int, webassembly.SymInfo] = {}


        # Dense list of the subset of defined, non-absolute data symbols. They
        # cover as much of the data section as we have information about, and
        # ignore segments. The indexes are only used for binary search.
        DataSymInfo = namedtuple('DataSymInfo', ['sym_index', 'sym', 'datasec_offset'])
        self.data_syms_list: list[DataSymInfo] = []

        # TODO: needed?
        self.segment_index_to_sym_index = {}

        segment_datasec_offsets = []
        data_section_file_offset = module.get_section(webassembly.SecType.DATA).offset
        for seg in module.get_segments():
            segment_datasec_offsets.append(seg.offset - data_section_file_offset)

        for i, sym in enumerate(self.symtab):
            if sym.flags & (webassembly.SymbolFlags.SYM_ABSOLUTE | webassembly.SymbolFlags.SYM_UNDEFINED):
                continue
            self.name_map[sym.name] = sym
            if sym.kind == webassembly.SymbolKind.FUNCTION:
                self.function_syms[sym.index] = sym
            elif sym.kind == webassembly.SymbolKind.DATA:
                symbol_datasec_offset = segment_datasec_offsets[sym.index] + sym.offset
                self.data_syms_list.append(DataSymInfo(i, sym, symbol_datasec_offset))
                self.segment_index_to_sym_index[sym.index] = i
        self.data_syms_list.sort(key=lambda s: s.datasec_offset)


    def sym_by_name(self, name: str) -> webassembly.SymInfo | None:
        return self.name_map.get(name)
        return None
        raise Exception(f'symbol {name} not found')

    def sym_by_module_index(self, kind, index):
        if kind == webassembly.SymbolKind.FUNCTION:
            return self.function_syms[index]
        elif kind == webassembly.SymbolKind.DATA:
            return self.segment_index_to_sym_index[index]
        raise Exception(f'bad symbol kind: {webassembly.SymbolKind(kind).name}')

    def __getitem__(self, key) -> webassembly.SymInfo:
        return self.symtab[key]


    def data_sym_from_section_offset(self, section_offset) -> int:
        def isearch(start, end):
            i = (end + start) // 2
            data_sym = self.data_syms_list[i]
            if section_offset >= data_sym.datasec_offset + data_sym.sym.size:
                if i < len(self.data_syms_list) - 1 and section_offset < self.data_syms_list[i + 1].datasec_offset:
                    print(f'warning, offset {section_offset} falls in between symbols (after {data_sym.sym.name})')
                    # TODO: what to actually do here?
                    return i
                if start == len(self.data_syms_list):
                    raise Exception(f'section offset {section_offset} too large')
                return isearch(i + 1, end)
            elif section_offset < data_sym.datasec_offset:
                if end == 0:
                    raise Exception(f'section offset {section_offset} too small, at {i}')
                return isearch(start, i)
            else:
                return i

        result = isearch(0, len(self.data_syms_list))
        return self.data_syms_list[result].sym_index


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
    def __init__(self):
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
    Tab = Symtab(module)
    code_relocs = module.get_relocs('CODE')
    data_relocs = module.get_relocs('DATA')
    func_map = CodeMap(module)
    check_data_syms(Tab)
    callgraph = Callgraph()

    for reloc in code_relocs:
        if VERBOSE:
            print(f'CODE reloc off {reloc.offset} idx {reloc.index} type {webassembly.RelocType(reloc.reloc_type).name} sym {Tab[reloc.index]}')
        if reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB and reloc.reloc_type != webassembly.RelocType.GLOBAL_INDEX_LEB:
            source: int = func_map.search(reloc.offset)
            ssym = Tab.sym_by_module_index(webassembly.SymbolKind.FUNCTION, source)
            fname = ssym.name
            if VERBOSE:
                print(f' source function {source} fname {fname} sym {ssym}')
                print(f'  to symbol {Tab[reloc.index]}')
            if ssym and ssym.flags & webassembly.SymbolFlags.BINDING_LOCAL == 0:
                assert ssym.index == source, f'source {source} sym {ssym}'
            dsym = Tab[reloc.index]
            if VERBOSE:
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
            print(f'DATA reloc off {reloc.offset} idx {reloc.index} name {Tab[reloc.index]}')
        assert reloc.reloc_type != webassembly.RelocType.TYPE_INDEX_LEB
        data_section = module.get_section(webassembly.SecType.DATA)
        if reloc.offset > data_section.size:
            print(f'  reloc offset {reloc.offset} > data section size {data_section.size}')
            sys.exit(1)
        source = Tab.data_sym_from_section_offset(reloc.offset)
        if VERBOSE:
            print(f' source symbol {source} sym {ssym}')
            print(f'  to symbol {Tab[reloc.index]}')
        #name = Tab.sym_by_module_index(webassembly.SymbolKind.DATA, source).name
        name = Tab[source].name
        snode = callgraph.get(webassembly.SymbolKind.DATA, source, name)
        dsym = Tab[reloc.index]
        dnode = callgraph.get(dsym.kind, dsym.index, dsym.name)
        if 'TABLE_INDEX' in reloc.reloc_type.name:
            snode.add_indirect_edge(dnode)
        else:
            snode.add_edge(dnode)
        if VERBOSE:
            print(f'{snode.name} (D) -> {dsym.name} ({webassembly.SymbolKind(dsym.kind).name}) via {reloc.reloc_type.name}')

    return callgraph


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
        check_names(module)
        callgraph = symtab_stats(module)
        entry = ['gzread', 'gzopen']
        def setPrint(s):
            print([f.name for f in sorted(s, key=lambda x:x.name)])
        #entry = ['foo', 'bar']
        r = callgraph.get_reachable_from_funcs(entry)
        print(f'reachable from {entry}')
        setPrint(r)
        anchor = '_ZN4wasm19OptimizationOptions9runPassesERNS_6ModuleE'
        #anchor = 'baz'
        print(f'reachable from {anchor}')
        pr = callgraph.get_reachable_from_funcs([anchor])
        #setPrint(pr)
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

