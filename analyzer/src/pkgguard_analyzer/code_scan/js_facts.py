"""Reads JavaScript structure with tree-sitter to find risky capabilities. Parses only; never runs code."""

from dataclasses import dataclass, field

import tree_sitter_javascript
from tree_sitter import Language, Node, Parser

JAVASCRIPT = Language(tree_sitter_javascript.language())
PARSER = Parser(JAVASCRIPT)

NETWORK_MODULES = frozenset({"http", "https", "http2", "net", "tls", "dgram", "dns"})
EXEC_FUNCTIONS = frozenset({"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"})
VM_FUNCTIONS = frozenset({"runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script"})
RECON_FUNCTIONS = frozenset({"hostname", "userInfo", "networkInterfaces"})
NETWORK_GLOBALS = frozenset({"fetch", "XMLHttpRequest", "WebSocket"})
GLOBAL_OBJECTS = frozenset({"global", "globalThis", "window", "self"})
DECODE_ENCODINGS = frozenset({"base64", "base64url", "hex"})
MIN_CHAR_CODES = 8
SNIPPET_CHARS = 200


@dataclass
class Location:
    line: int
    snippet: str


@dataclass
class StringLiteral:
    raw: str
    location: Location


@dataclass
class FileFacts:
    modules: dict[str, Location] = field(default_factory=dict)
    dynamic_code: list[Location] = field(default_factory=list)
    exec_calls: list[Location] = field(default_factory=list)
    network_calls: list[Location] = field(default_factory=list)
    env_dumps: list[Location] = field(default_factory=list)
    env_copies: list[Location] = field(default_factory=list)
    env_names: set[str] = field(default_factory=set)
    recon_calls: list[Location] = field(default_factory=list)
    decode_calls: list[Location] = field(default_factory=list)
    strings: list[StringLiteral] = field(default_factory=list)
    parse_errors: bool = False

    @property
    def uses_network(self) -> bool:
        return bool(self.network_calls) or any(module in NETWORK_MODULES for module in self.modules)


def extract_facts(source: bytes) -> FileFacts:
    return _Extractor(source).run()


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text is not None else ""


def _same(a: Node | None, b: Node) -> bool:
    return a is not None and (a.start_byte, a.end_byte) == (b.start_byte, b.end_byte)


def _module_base(name: str) -> str:
    return name.removeprefix("node:").split("/")[0]


class _Extractor:
    def __init__(self, source: bytes):
        self.lines = source.split(b"\n")
        self.source = source
        self.facts = FileFacts()
        self.module_aliases: dict[str, str] = {}
        self.imported_functions: dict[str, tuple[str, str]] = {}
        self.calls: list[Node] = []
        self.constructions: list[Node] = []

    def run(self) -> FileFacts:
        tree = PARSER.parse(self.source)
        self.facts.parse_errors = tree.root_node.has_error
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            kind = node.type
            if kind == "call_expression":
                self.calls.append(node)
                if module := self._required_module(node):
                    self.facts.modules.setdefault(module, self._location(node))
            elif kind == "new_expression":
                self.constructions.append(node)
            elif kind == "variable_declarator":
                self._declarator(node)
            elif kind == "import_statement":
                self._import(node)
            elif kind == "member_expression":
                self._member(node)
            elif kind in ("string", "template_string"):
                self._string(node)
            stack.extend(reversed(node.children))

        # Classify calls after the walk, once every require/import binding is known.
        for call in self.calls:
            self._classify_call(call)
        for construction in self.constructions:
            self._classify_construction(construction)
        return self.facts

    def _location(self, node: Node) -> Location:
        row, column = node.start_point[0], node.start_point[1]
        line = self.lines[row] if row < len(self.lines) else b""
        start = max(0, column - 60)
        return Location(row + 1, line[start : start + SNIPPET_CHARS].decode("utf-8", "replace").strip())

    def _string_value(self, node: Node | None) -> str | None:
        return _text(node)[1:-1] if node is not None and node.type == "string" else None

    def _required_module(self, call: Node) -> str | None:
        function = call.child_by_field_name("function")
        if function is None or not (
            (function.type == "identifier" and _text(function) == "require") or function.type == "import"
        ):
            return None
        arguments = call.child_by_field_name("arguments")
        if arguments is None or arguments.named_child_count == 0:
            return None
        name = self._string_value(arguments.named_children[0])
        return _module_base(name) if name else None

    def _declarator(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name is None or value is None:
            return
        if value.type == "call_expression" and (module := self._required_module(value)):
            if name.type == "identifier":
                self.module_aliases[_text(name)] = module
            elif name.type == "object_pattern":
                for part in name.named_children:
                    if part.type == "shorthand_property_identifier_pattern":
                        self.imported_functions[_text(part)] = (module, _text(part))
                    elif part.type == "pair_pattern":
                        key, local = part.child_by_field_name("key"), part.child_by_field_name("value")
                        if local is not None and local.type == "identifier":
                            self.imported_functions[_text(local)] = (module, _text(key))
        elif value.type == "member_expression" and name.type == "identifier":
            target = value.child_by_field_name("object")
            if target is not None and target.type == "call_expression" and (module := self._required_module(target)):
                self.imported_functions[_text(name)] = (module, _text(value.child_by_field_name("property")))

    def _import(self, node: Node) -> None:
        name = self._string_value(node.child_by_field_name("source"))
        if not name:
            return
        module = _module_base(name)
        self.facts.modules.setdefault(module, self._location(node))
        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        if clause is None:
            return
        for part in clause.named_children:
            if part.type == "identifier":
                self.module_aliases[_text(part)] = module
            elif part.type == "namespace_import":
                alias = next((c for c in part.named_children if c.type == "identifier"), None)
                if alias is not None:
                    self.module_aliases[_text(alias)] = module
            elif part.type == "named_imports":
                for specifier in part.named_children:
                    if specifier.type != "import_specifier":
                        continue
                    imported = specifier.child_by_field_name("name")
                    local = specifier.child_by_field_name("alias") or imported
                    self.imported_functions[_text(local)] = (module, _text(imported))

    def _member(self, node: Node) -> None:
        if _text(node.child_by_field_name("object")) != "process" or _text(node.child_by_field_name("property")) != "env":
            return
        parent = node.parent
        if parent is not None:
            # process.env.HOME or process.env["HOME"] reads one variable, which is normal.
            if parent.type in ("member_expression", "subscript_expression") and _same(parent.child_by_field_name("object"), node):
                if name := self._property_name(parent):
                    self.facts.env_names.add(name)
                return
            # const { HOME } = process.env also reads specific variables.
            if parent.type == "variable_declarator" and (pattern := parent.child_by_field_name("name")) is not None:
                if pattern.type == "object_pattern":
                    for part in pattern.named_children:
                        if part.type == "shorthand_property_identifier_pattern":
                            self.facts.env_names.add(_text(part))
                        elif part.type == "pair_pattern":
                            self.facts.env_names.add(_text(part.child_by_field_name("key")).strip("\"'"))
                    return
            # { ...process.env, X: 1 } or { env: process.env } passes the environment on to a child process.
            if parent.type == "spread_element" or (
                parent.type == "pair" and _text(parent.child_by_field_name("key")) == "env"
            ):
                self.facts.env_copies.append(self._location(node))
                return
        self.facts.env_dumps.append(self._location(node))

    def _string(self, node: Node) -> None:
        if node.type == "string":
            raw = _text(node)[1:-1]
        else:
            raw = "".join(_text(c) for c in node.named_children if c.type in ("string_fragment", "escape_sequence"))
        if raw:
            self.facts.strings.append(StringLiteral(raw, self._location(node)))

    def _property_name(self, node: Node) -> str | None:
        if node.type == "member_expression":
            return _text(node.child_by_field_name("property"))
        if node.type == "subscript_expression":
            return self._string_value(node.child_by_field_name("index"))
        return None

    def _module_call(self, module: str, function: str, node: Node) -> None:
        if module == "child_process" and function in EXEC_FUNCTIONS:
            self.facts.exec_calls.append(self._location(node))
        elif module in NETWORK_MODULES:
            self.facts.network_calls.append(self._location(node))
        elif module == "vm" and function in VM_FUNCTIONS:
            self.facts.dynamic_code.append(self._location(node))
        elif module == "os" and function in RECON_FUNCTIONS:
            self.facts.recon_calls.append(self._location(node))

    def _classify_call(self, call: Node) -> None:
        function = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        if function is None:
            return

        if function.type == "identifier":
            name = _text(function)
            if name in ("eval", "Function"):
                self.facts.dynamic_code.append(self._location(call))
            elif name in NETWORK_GLOBALS:
                self.facts.network_calls.append(self._location(call))
            elif name == "atob":
                self.facts.decode_calls.append(self._location(call))
            elif name in self.imported_functions:
                self._module_call(*self.imported_functions[name], call)
            return

        property_name = self._property_name(function)
        target = function.child_by_field_name("object")
        if property_name is None or target is None:
            return
        target_text = _text(target)
        if property_name in ("eval", "Function") and target_text in GLOBAL_OBJECTS:
            self.facts.dynamic_code.append(self._location(call))
        elif target.type == "identifier" and target_text in self.module_aliases:
            self._module_call(self.module_aliases[target_text], property_name, call)
        elif target.type == "call_expression" and (module := self._required_module(target)):
            self._module_call(module, property_name, call)
        elif target_text == "Buffer" and property_name == "from" and arguments is not None:
            if arguments.named_child_count >= 2 and self._string_value(arguments.named_children[1]) in DECODE_ENCODINGS:
                self.facts.decode_calls.append(self._location(call))
        elif target_text == "String" and property_name == "fromCharCode" and arguments is not None:
            if arguments.named_child_count >= MIN_CHAR_CODES:
                self.facts.decode_calls.append(self._location(call))

    def _classify_construction(self, node: Node) -> None:
        constructor = node.child_by_field_name("constructor")
        if constructor is None:
            return
        name = _text(constructor)
        if name == "Function":
            self.facts.dynamic_code.append(self._location(node))
        elif name in NETWORK_GLOBALS:
            self.facts.network_calls.append(self._location(node))
        elif constructor.type == "identifier" and self.imported_functions.get(name) == ("vm", "Script"):
            self.facts.dynamic_code.append(self._location(node))
        elif constructor.type == "member_expression":
            target = _text(constructor.child_by_field_name("object"))
            if self.module_aliases.get(target) == "vm" and _text(constructor.child_by_field_name("property")) == "Script":
                self.facts.dynamic_code.append(self._location(node))
