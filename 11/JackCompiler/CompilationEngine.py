from VMWriter import VMWriter
from SymbolTable import SymbolTable
from lib.Token import Token
from lib.Lib import safe_true, get_op

from lib.Errs import (
    bad_var_dec,
    start_err,
    bad_token,
    bad_class_token,
    bad_sub_dec,
    bad_statement,
)


class CompilationEngine:
    def __init__(self, input_path: str, output_path: str):
        self.token = Token()
        self.prev_token = None
        self.count = 0

        self.file_in = None

        self.vw = VMWriter(output_path)
        self.sym_table = SymbolTable()

        self.class_name = None
        self.sub_name = None
        self.sub_return_type = None
        self.is_method = None

        self.call_arg_count = None
        self.loop_count = 0
        self.if_count = 0

        try:
            with open(input_path, "r") as self.file_in:
                self.set_token()
                if self.get_token() != "<tokens>":
                    raise Exception(start_err(self.get_token()))

                while safe_true(self.count):
                    self.set_token()
                    if self.get_token() is None:
                        raise Exception("encountered NULL while compiling file")

                    if self.token.is_class_dec():
                        self.compile_class()
                    elif self.get_token() == "</tokens>":
                        break
                    else:
                        raise Exception(bad_token(self.get_token))
        except Exception as err:
            print(err)
        finally:
            # self.sym_table.print_table("class")
            self.vw.close()

    def compile_class(self):
        """Compiles a complete class"""
        while safe_true(self.count):
            self.set_token()
            if not self.get_token():
                raise Exception("Encountered NULL token while compiling class")

            if self.token.is_block_end():
                break

            if self.token_type() == "identifier":
                self.class_name = self.token_body()
            elif self.token.is_block_start():
                pass
            elif self.token.is_class_var_dec():
                self.compile_class_var_dec()
            elif self.token.is_subroutine():
                self.compile_subroutine_dec()
            else:
                raise Exception(bad_class_token(self.get_token(), self.count))

    def compile_class_var_dec(self):
        """Compiles a static variable declaration or field declaration"""
        var_kind, var_type, var_name = self.token_body().upper(), None, None
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception(bad_var_dec())
            if self.token.is_statement_end():
                break

            if var_type is None:
                var_type = self.token_body()
            elif var_name is None:
                var_name = self.token_body()
            elif self.token_type() == "symbol" and self.token_body() == ",":
                self.sym_table.define(var_name, var_type, var_kind)
                var_name = None
        self.sym_table.define(var_name, var_type, var_kind)

    def compile_subroutine_dec(self):
        """Compiles a complete method, function, or constructor"""

        self.sub_name = None
        self.sym_table.start_subroutine()
        if self.token_body() == "method":
            self.sym_table.define("this", self.class_name, "ARG")
            self.is_method = True

        self.sub_return_type = None

        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception(bad_sub_dec())

            if self.token.is_block_end():
                break

            if self.token_type() == "symbol":
                if self.token_body() == "(":
                    self.compile_parameter_list()
                    continue
                if self.token_body() == "{":
                    self.compile_subroutine_body()
                    break

            if self.sub_return_type is None:
                self.sub_return_type = self.token_body()
            elif self.sub_name is None:
                self.sub_name = self.token_body()

    def compile_parameter_list(self):
        """Compiles a possibly empty parameter list. Does not handle enclosing '()'"""
        var_type, var_name = None, None

        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling parameter list")
            if self.token.is_parens_end():
                if var_type is not None and var_name is not None:
                    self.sym_table.define(var_name, var_type, "ARG")
                    var_type, var_name = None, None
                return

            if var_type is None:
                var_type = self.token_body()
            elif var_name is None:
                var_name = self.token_body()
            else:
                self.sym_table.define(var_name, var_type, "ARG")
                var_type, var_name = None, None

    def compile_subroutine_body(self):
        """Compiles a subroutine's body"""
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling subroutine body")

            if self.token_type() == "keyword" and self.token_body() == "var":
                self.compile_var_dec()
                continue

            func_name = f"{self.class_name}.{self.sub_name}"
            local_count = self.sym_table.var_count("VAR")
            self.vw.write_function(func_name, local_count)
            if self.sub_name == "new":
                self.vw.write_push("CONST", self.sym_table.var_count("FIELD"))
                self.vw.write_call("Memory.alloc", 1)
                self.vw.write_pop("POINTER", 0)

            if self.is_method:
                self.is_method = None
                self.vw.write_push("ARG", 0)
                self.vw.write_pop("POINTER", 0)
            self.compile_statements()
            break

    def compile_var_dec(self):
        """Compiles a var declaration"""
        var_type, var_name = None, None
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling variable declaration")
            if self.token.is_statement_end():
                break

            if var_type is None:
                var_type = self.token_body()
            elif var_name is None:
                var_name = self.token_body()
            elif self.token_type() == "symbol" and self.token_body() == ",":
                self.sym_table.define(var_name, var_type, "VAR")
                var_name = None
        self.sym_table.define(var_name, var_type, "VAR")

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        while safe_true(self.count):
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling statements")

            if self.token.is_block_end():
                return
            if self.token_type() == "keyword" and self.token_body() == "let":
                self.compile_let()
            elif self.token_type() == "keyword" and self.token_body() == "if":
                self.compile_if()
                continue
            elif self.token_type() == "keyword" and self.token_body() == "while":
                self.compile_while()
                continue
            elif self.token_type() == "keyword" and self.token_body() == "do":
                self.compile_do()
            elif self.token_type() == "keyword" and self.token_body() == "return":
                self.compile_return()
                break
            else:
                raise Exception(bad_statement(self.get_token(), self.count))
            self.set_token()
        self.set_token()

    def compile_let(self):
        # Compiles a let statement
        self.set_token()
        var_kind = self.sym_table.kind_of(self.token_body())
        var_idx = self.sym_table.index_of(self.token_body())

        next_token = Token(self.look_ahead())
        if next_token.is_arr_start():
            self.set_token()
            # self.write()
            self.compile_expression()
            # self.write()
        self.set_token()
        self.compile_expression()
        self.vw.write_pop(var_kind, var_idx)

    def compile_if(self):
        # Compiles an if statement, possibly with a trailing else clause
        open_if = True
        self.if_count += 1
        if_label = f"IF_{self.if_count}"
        while safe_true(self.count):
            self.set_token()

            if self.get_token() is None:
                raise Exception("encountered NULL while compiling if statement")

            elif self.token.is_parens_start():
                self.compile_expression()
                self.vw.write_arithmetic("NOT")
                self.vw.write_if(f"{if_label}_ELSE")
            elif self.token.is_block_start():
                self.set_token()
                self.compile_statements()
            elif self.token_type() == "keyword" and self.token_body() == "else":
                self.vw.write_goto(f"{if_label}_END")
                open_if = False
                self.vw.write_label(f"{if_label}_ELSE")
            else:
                if open_if:
                    open_if = False
                    self.vw.write_label(f"{if_label}_ELSE")
                break
        self.vw.write_label(f"{if_label}_END")

    def compile_while(self):
        # Compiles a while statement
        self.loop_count += 1
        loop_label = f"LOOP_{self.loop_count}"
        self.vw.write_label(loop_label)

        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling while statement")
            elif self.token.is_parens_start():
                self.compile_expression()

                self.vw.write_arithmetic("NOT")
                self.vw.write_if(f"{loop_label}_END")
            elif self.token.is_block_start():
                self.set_token()
                self.compile_statements()
                self.vw.write_goto(loop_label)
            else:
                break
        self.vw.write_label(f"{loop_label}_END")

    def compile_do(self):
        # Compiles a do statement
        call_name = None
        call = ""
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling do statement")

            if self.token.is_statement_end():
                break
            elif self.token.is_parens_start():
                if call_name is not None:
                    self.vw.write_push(
                        self.sym_table.kind_of(call_name),
                        self.sym_table.index_of(call_name),
                    )
                if "." not in call:
                    call = f"{self.class_name}.{call}"
                    call_name = "this"
                    self.vw.write_push("POINTER", 0)
                self.compile_expression_list()
            else:
                if len(call) == 0:
                    is_var = self.sym_table.type_of(self.token_body()) != "NONE"
                    call_name = self.token_body() if is_var else None
                    call += (
                        self.token_body()
                        if not is_var
                        else self.sym_table.type_of(self.token_body())
                    )
                else:
                    call += self.token_body()
        self.call_arg_count += 0 if call_name is None else 1
        self.vw.write_call(call, self.call_arg_count)
        self.call_arg_count = None
        self.vw.write_pop("TEMP", 0)

    def compile_return(self):
        # Compiles a return statement
        next_token = self.look_ahead()
        if next_token == "<symbol> ; </symbol>":
            if self.sub_return_type != "void":
                raise Exception("Expected return values but encountered VOID.")
            self.set_token()
            self.vw.write_push("CONST", 0)
            self.vw.write_return()
            return

        if self.sub_name == "new":
            self.set_token()
            if self.token_body() != "this":
                raise Exception("Constructors must return THIS")
            self.set_token()
            self.vw.write_push("POINTER", 0)
            self.vw.write_return()
            return

        while safe_true(self.count):
            if self.sub_return_type == "void":
                raise Exception("Expected VOID return but encountered value(s).")
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling return statement")
            if self.token.is_statement_end():
                break
            self.compile_expression()
            self.vw.write_return()

    def compile_expression(self):
        # Compiles an expression
        op = None
        self.set_token()
        self.compile_term()
        while safe_true(self.count):
            self.set_token()
            if self.token.is_expr_end():
                if op is None:
                    return
                if op == "*":
                    self.vw.write_call("Math.multiply", 2)
                elif op == "/":
                    self.vw.write_call("Math.divide", 2)
                else:
                    self.vw.write_arithmetic(get_op(op))
                return
            op = self.token_body()

            self.set_token()
            self.compile_term()

    def compile_term(self):
        # Compiles a term.
        if self.token.is_unary_op():
            op = self.token_body()
            self.set_token()
            self.compile_term()
            self.vw.write_arithmetic("NOT" if op == "~" else "NEG")

        elif self.token.is_parens_start():
            self.compile_expression()

        elif self.token_type() == "identifier":
            next_token = Token(self.look_ahead())
            if next_token.is_arr_start():
                self.set_token()
                # self.write()
                self.compile_expression()
                # self.write()
            elif next_token.is_parens_start():
                self.set_token()
                self.compile_expression_list()
                # self.write()
            elif next_token.token_type == "symbol" and next_token.token_body == ".":
                call = self.token_body()
                self.set_token()
                call = call + self.token_body()
                self.set_token()
                call = call + self.token_body()
                self.set_token()
                self.compile_expression_list()
                self.vw.write_call(call, self.call_arg_count)
                self.call_arg_count = None
            else:
                var_kind = self.sym_table.kind_of(self.token_body())
                var_idx = self.sym_table.index_of(self.token_body())
                self.vw.write_push(var_kind, var_idx)

        else:
            self.push_term()

    def compile_expression_list(self):
        # Compiles a possibly empty comma-separated list of expressions
        self.call_arg_count = 0
        next_token = Token(self.look_ahead())
        if next_token.is_parens_end():
            self.set_token()
            return

        while safe_true(self.count):
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling expression list")
            if self.token.is_parens_end():
                break

            self.call_arg_count = self.call_arg_count + 1
            self.compile_expression()

    def set_token(self, x: int = 1):
        self.count += x
        if x == 1:
            self.prev_token = Token(self.get_token())
        token = self.file_in.readline().strip()
        self.token.set(token)

    def pointer(self) -> int:
        return self.file_in.tell()

    def look_ahead(self) -> str:
        pointer = self.pointer()
        token = self.get_token()
        self.set_token(0)
        new_token = self.get_token()
        self.file_in.seek(pointer)
        self.token.set(token)
        return new_token

    def get_token(self) -> str:
        return self.token.token

    def token_type(self) -> str:
        return self.token.token_type

    def token_body(self) -> str:
        return self.token.token_body

    def push_term(self) -> None:
        if self.token_type() == "integerConstant":
            self.vw.write_push("CONST", int(self.token_body()))
        elif self.token_type() == "keyword":
            if self.token_body() == "true":
                self.vw.write_push("CONST", 0)
                self.vw.write_arithmetic("NOT")
            elif self.token_body() == "false":
                self.vw.write_push("CONST", 0)
            elif self.token_body() == "this":
                self.vw.write_push("POINTER", 0)
            else:
                raise Exception(
                    f"Unrecognized keyword encountered while pushing term: {self.token_body()}"
                )
        else:
            raise Exception(
                f"Unrecognized token_type while pushing term: {self.token_type()}"
            )
