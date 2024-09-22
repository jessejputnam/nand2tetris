from typing import Literal

kind_input = Literal["STATIC", "FIELD", "ARG", "VAR"]
kind_output = Literal["STATIC", "FIELD", "ARG", "VAR", "NONE"]

var = {
    "STATIC": "static",
    "FIELD": "field",
    "VAR": "local",
    "ARG": "argument",
    "argument": "ARG",
    "local": "VAR",
    "field": "FIELD",
    "static": "STATIC",
}


class SymbolTable:
    def __init__(self):
        self.class_vars = {}
        self.sub_vars = {}

    def start_subroutine(self) -> None:
        # Starts a new subroutine scope -- i.e. resets the subroutine's symbol table
        self.sub_vars = {}
        return

    def define(self, name: str, type: str, kind: kind_input) -> None:
        # Defines a new identifier given name, type, and kind, then assigns it a running index
        # kinds: [STATIC, FIELD, ARG, VAR] -- STATIC and FIELD have a class scope, ARG and VAR have subroutine scope
        idx = self.var_count(kind)
        self.sub_vars[name] = {"type": type, "kind": var[kind], "idx": idx}
        return

    def var_count(self, kind: str) -> int:
        # Returns the number of variables of the given kind already defined in the current scope
        if kind not in ["STATIC", "FIELD", "ARG", "VAR"]:
            raise Exception(
                f"Unrecognized variable type <{kind}> checking variable count in Symbol Table."
            )

        scope = self.class_vars if kind in ["STATIC", "FIELD"] else self.sub_vars
        return len([x for x in scope.values() if x["kind"] == var[kind]])

    def kind_of(self, name: str) -> kind_output:
        # Returns the kind of the names identifier in the current scope. If identifier unknown
        # in the current scope, returns NONE
        if name in self.sub_vars:
            return var[self.sub_vars[name]["kind"]]
        elif name in self.class_vars:
            return var[self.class_vars[name]["kind"]]
        else:
            return "NONE"

    def type_of(self, name: str) -> str:
        # Returns the type of the named identifier in the current scope
        if name in self.sub_vars:
            return self.sub_vars[name]["type"]
        elif name in self.class_vars:
            return self.class_vars[name]["type"]
        else:
            return "NONE"

    def index_of(self, name: str) -> int:
        # Returns the index assigned to the named identifer
        if name in self.sub_vars:
            return self.sub_vars[name]["idx"]
        elif name in self.class_vars:
            return self.class_vars[name]["idx"]
        else:
            return "NONE"
