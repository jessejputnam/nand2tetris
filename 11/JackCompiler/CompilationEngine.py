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
        self.file_in = None
        self.vw = VMWriter(output_path)
        self.sym_table = SymbolTable()
        self.class_name = None
        self.subroutine_name = None
        self.prev_token = None
        self.count = 0

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
            self.vw.close()

    def compile_class(self):
        # Compiles a complete class
        # self.write("<class>")
        # self.write()

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
        # self.write()
        # self.write("</class>")

    def compile_class_var_dec(self):
        # Compiles a static variable declaration or field declaration
        # self.write("<classVarDec>")
        # self.write()
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception(bad_var_dec())
            if self.token.is_statement_end():
                break
            # self.write()
        # self.write()
        # self.write("</classVarDec>")

    def compile_subroutine_dec(self):
        # Compiles a complete method, function, or constructor
        self.subroutine_name = None
        self.sym_table.define("this", self.class_name, "ARG")
        return_type = None

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

            if return_type is None:
                return_type = self.token_body()
            elif self.subroutine_name is None:
                self.subroutine_name = self.token_body()

    def compile_parameter_list(self):
        # Compiles a possibly empty parameter list. Does not handle enclosing "()"
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling parameter list")
            if self.token.is_parens_end():
                break

    def compile_subroutine_body(self):
        # Compiles a subroutine's body
        # self.write("<subroutineBody>")
        # self.write()
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling subroutine body")

            if self.token_type() == "keyword" and self.token_body() == "var":
                self.compile_var_dec()
                continue

            self.vw.write_function(
                f"{self.class_name}.{self.subroutine_name}",
                self.sym_table.var_count("VAR"),
            )
            self.compile_statements()
            break

        # self.write()
        # self.write("</subroutineBody>")

    def compile_var_dec(self):
        # Compiles a var declaration
        # self.write("<varDec>")
        # self.write()
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling variable declaration")
            if self.token.is_statement_end():
                break
            # self.write()
        # self.write()
        # self.write("</varDec>")

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        # self.write("<statements>")
        while safe_true(self.count):
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling statements")

            if self.token.is_block_end():
                # self.write("</statements>")
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
                # self.write("</statements>")
                break
            else:
                raise Exception(bad_statement(self.get_token(), self.count))
            self.set_token()
        self.set_token()

    def compile_let(self):
        # Compiles a let statement
        # self.write("<letStatement>")
        # self.write()
        self.set_token()
        # self.write()
        next_token = Token(self.look_ahead())
        if next_token.is_arr_start():
            self.set_token()
            # self.write()
            self.compile_expression()
            # self.write()
        self.set_token()
        # self.write()
        self.compile_expression()
        # self.write()
        # self.write("</letStatement>")

    def compile_if(self):
        # Compiles an if statement, possibly with a trailing else clause
        # self.write("<ifStatement>")
        # self.write()

        while safe_true(self.count):
            self.set_token()

            if self.get_token() is None:
                raise Exception("encountered NULL while compiling if statement")

            elif self.token.is_parens_start():
                # self.write()
                self.compile_expression()
                # self.write()
            elif self.token.is_block_start():
                # self.write()
                self.set_token()
                self.compile_statements()
                # self.write()
            elif self.token_type() == "keyword" and self.token_body() == "else":
                # self.write()
                pass
            else:
                break
        # self.write("</ifStatement>")

    def compile_while(self):
        # Compiles a while statement
        # self.write("<whileStatement>")
        # self.write()

        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling while statement")
            elif self.token.is_parens_start():
                # self.write()
                self.compile_expression()
                # self.write()
            elif self.token.is_block_start():
                # self.write()
                self.set_token()
                self.compile_statements()
                # self.write()
            else:
                break
        # self.write("</whileStatement>")

    def compile_do(self):
        # Compiles a do statement
        call = ""
        while safe_true(self.count):
            self.set_token()
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling do statement")

            if self.token.is_statement_end():
                break
            elif self.token.is_parens_start():
                self.compile_expression_list()
            else:
                call += self.token_body()
        print(call)
        # self.write()
        # self.write("</doStatement>")

    def compile_return(self):
        # Compiles a return statement
        # self.write("<returnStatement>")
        # self.write()
        next_token = self.look_ahead()
        if next_token == "<symbol> ; </symbol>":
            self.set_token()
            # self.write()
            # self.write("</returnStatement>")
            return

        while safe_true(self.count):
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling return statement")
            if self.token.is_statement_end():
                break
            self.compile_expression()
        # self.write()
        # self.write("</returnStatement>")

    def compile_expression(self):
        # Compiles an expression
        # self.write("<expression>")
        op = None
        self.set_token()
        self.compile_term()
        while safe_true(self.count):
            self.set_token()
            if self.token.is_expr_end():
                print(op)
                if op == "*":
                    self.vw.write_call("Math.multiply", 2)
                elif op == "/":
                    self.vw.write_call("Math.divide", 2)
                else:
                    self.vw.write_arithmetic(get_op(op))
                return
            op = self.token_body()
            print(op)
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
                self.set_token()
                # self.write()
                self.set_token()
                # self.write()
                self.set_token()
                self.compile_expression_list()
        else:
            self.push_term()
        #     self.write()
        # self.write("</term>")

    def compile_expression_list(self):
        # Compiles a possibly empty comma-separated list of expressions
        # self.write()
        # self.write("<expressionList>")
        next_token = Token(self.look_ahead())
        if next_token.is_parens_end():
            # self.write("</expressionList>")
            self.set_token()
            # self.write()
            return

        while safe_true(self.count):
            if self.get_token() is None:
                raise Exception("encountered NULL while compiling expression list")
            if self.token.is_parens_end():
                break

            self.compile_expression()
            ###########################
            # if self.token.is_parens_end(): # MIGHT NEED DO NOT REMOVE
            #     break
            #############################

        #     self.write()
        # self.write("</expressionList>")
        # self.write()

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
