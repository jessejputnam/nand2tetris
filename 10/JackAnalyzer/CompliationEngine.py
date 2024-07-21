from Token import Token


class CompilationEngine:
    def __init__(self, input_path: str, output_path: str):
        self.t: Token = Token()
        # self.t.token_body = None
        # self.t.token_type = None
        self.file_in = None
        self.file_out = None
        self.prev_token = None
        self.prefix = 0
        self.count = 0

        with open(input_path, "r") as self.file_in:
            with open(output_path, "w+") as self.file_out:
                self.set_token()
                if self.t.token != "<tokens>":
                    raise Exception(f"encountered unexpected token while starting file compilation: {self.t.token}")
                
                while True:
                    self.set_token()
                    if self.t.token is None:
                        raise Exception("encountered NULL while compiling file")

                    if self.is_class_dec():
                        self.compile_class()
                    elif self.t.token == "</tokens>":
                        break
                    else:
                        raise Exception(f"Encountered incorrect token while compiling file: {self.t.token}")

    def compile_class(self):
        # Compiles a complete class
        self.write("<class>")
        self.write()

        while True:
            self.set_token()
            if not self.t.token:
                raise Exception("Encountered NULL token while compiling class")

            if self.is_block_end():
                break

            if self.t.token_type == "identifier":
                self.write()
            elif self.is_block_start():
                self.write()
            elif self.t.token_type == "keyword" and self.t.token_body in ["static", "field"]:
                self.compile_class_var_dec()
            elif self.is_subroutine():
                self.compile_subroutine_dec()
            else:
                raise Exception(f"Encountered unexpected token while compiling class at line {self.count} \n{self.t.token}")
        self.write()
        self.write("</class>")

    def compile_class_var_dec(self):
        # Compiles a static variable declaration or field declaration
        self.write("<classVarDec>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("Encountered incorrect token while compiling variable declaration")
            if self.is_statement_end():
                break
            self.write()
        self.write()
        self.write("</classVarDec>")

    def compile_subroutine_dec(self):
        # Compiles a complete method, function, or constructor
        self.write("<subroutineDec>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling subroutine declaration")
            if self.is_block_end():
                break

            if self.t.token_type == "symbol":
                if self.t.token_body == "(":
                    self.compile_parameter_list()
                    continue
                if self.t.token_body == "{":
                    self.compile_subroutine_body()
                    break
            self.write()
        self.write("</subroutineDec>")

    def compile_parameter_list(self):
        # Compiles a possibly empty parameter list. Does not handle enclosing "()"
        self.write()
        self.write("<parameterList>")
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling parameter list")
            if self.is_parens_end():
                break
            self.write()
        self.write("</parameterList>")
        self.write()

    def compile_subroutine_body(self):
        # Compiles a subroutine's body
        self.write("<subroutineBody>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling subroutine body")

            if self.t.token_type == "keyword" and self.t.token_body == "var":
                self.compile_var_dec()
                continue
            self.compile_statements()
            break

        self.write()
        self.write("</subroutineBody>")

    def compile_var_dec(self):
        # Compiles a var declaration
        self.write("<varDec>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling variable declaration")
            if self.is_statement_end():
                break
            self.write()
        self.write()
        self.write("</varDec>")

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        self.write("<statements>")
        while True:
            if self.t.token is None:
                raise Exception("encountered NULL while compiling statements")

            if self.is_block_end():
                self.write("</statements>")
                return
            if self.t.token_type == "keyword" and self.t.token_body == "let":
                self.compile_let()
            elif self.t.token_type == "keyword" and self.t.token_body == "if":
                self.compile_if()
                continue
            elif self.t.token_type == "keyword" and self.t.token_body == "while":
                self.compile_while()
                continue
            elif self.t.token_type == "keyword" and self.t.token_body == "do":
                self.compile_do()
            elif self.t.token_type == "keyword" and self.t.token_body == "return":
                self.compile_return()
                self.write("</statements>")
                break
            else:
                raise Exception(f"encountered unexpected token while compiling statements at line {self.count}\n{self.t.token}")
            self.set_token()
        self.set_token()

    def compile_let(self):
        # Compiles a let statement
        self.write("<letStatement>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling let statement")

            if self.t.token_type == "symbol" and self.t.token_body == "=":
                self.write()
                self.compile_expression()
                break
            self.write()

        self.write()
        self.write("</letStatement>")

    def compile_if(self):
        # Compiles an if statement, possibly with a trailing else clause
        self.write("<ifStatement>")
        self.write()
        
        while True:
            self.set_token()

            if self.t.token is None:
                raise Exception("encountered NULL while compiling if statement")
            
            elif self.is_parens_start():
                self.write()
                self.compile_expression()
                self.write()
            elif self.is_block_start():
                self.write()
                self.set_token()
                self.compile_statements()
                self.write()
            elif self.t.token_type == "keyword" and self.t.token_body == "else":
                self.write()
            else:
                break
        
        self.write("</ifStatement>")
        

    def compile_while(self):
        # Compiles a while statement
        self.write("<whileStatement>")
        self.write()

        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling while statement")
            elif self.is_parens_start():    
                self.write()
                self.compile_expression()
                self.write()
            elif self.is_block_start():
                self.write()
                self.set_token()
                self.compile_statements()
                self.write()
            else:
                break
        self.write("</whileStatement>")

    def compile_do(self):
        # Compiles a do statement
        self.write("<doStatement>")
        self.write()
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling do statement")

            if self.is_statement_end():
                break
            elif self.is_parens_start():
                self.compile_expression_list()
            else:
                self.write()

        self.write()
        self.write("</doStatement>")

    def compile_return(self):
        # Compiles a return statement
        self.write("<returnStatement>")
        self.write()
        next_token = self.look_ahead()
        if next_token == "<symbol> ; </symbol>":
            self.set_token()
            self.write()
            self.write("</returnStatement>")
            return
        
        while True:
            if self.t.token is None:
                raise Exception("encountered NULL while compiling return statement")
            if self.is_statement_end():
                break
            self.compile_expression()

        self.write()
        self.write("</returnStatement>")

    def compile_expression(self):
        # Compiles an expression
        self.write("<expression>")
        while True:
            self.set_token()
            if self.t.token is None:
                raise Exception("encountered NULL while compiling expression")
            if self.is_expr_end():
                break
            self.compile_term()

        self.write("</expression>")

    def compile_term(self):
        # Compiles a term.
        # If the current token is an identifier, routine must distinguish between:
        #   - a variable, an array entry, or a subroutine call.
        # A single look-ahead token, which may be [, (, or . suffices to distiguish
        # Any other is not a part of this term and should be advanced over
        self.write("<term>")
        self.write()
        self.write("</term>")

    def compile_expression_list(self):
        # Compiles a possibly empty comma-separated list of expressions
        self.write()
        self.write("<expressionList>")
        next_token = self.look_ahead()
        if next_token == "<symbol> ) </symbol>":
            self.set_token()
            self.write("</expressionList>")
            self.write()
            return

        while True:
            if self.t.token is None:
                raise Exception("encountered NULL while compiling expression list")
            if self.is_parens_end():
                break

            self.compile_expression()

            if self.is_parens_end():
                break
            self.write()
        self.write("</expressionList>")
        self.write()

    def write(self, token = None):
        if token is None:
            self.file_out.write(f"{"  "*self.prefix}{self.t.token}\n")
        else: 
            if token[1] == "/":
                self.untab()
                self.file_out.write(f"{"  "*self.prefix}{token}\n")
            else:
                self.file_out.write(f"{"  "*self.prefix}{token}\n")
                self.tab()

    def set_token(self):
        self.count += 1
        token = self.file_in.readline().strip()
        self.t.set(token)

    def is_class_dec(self) -> bool:
        return self.t.token_type == "keyword" and self.t.token_body == "class"

    def is_subroutine(self) -> bool:
        return self.t.token_type == "keyword" and self.t.token_body in [
            "method",
            "function",
            "constructor",
        ]

    def is_statement_end(self) -> bool:
        return self.t.token_type == "symbol" and self.t.token_body == ";"

    def is_block_end(self) -> bool:
        return self.t.token_type == "symbol" and self.t.token_body == "}"
    def is_block_start(self) -> bool:
        return self.t.token_type == "symbol" and self.t.token_body == "{"

    def is_parens_end(self) -> bool:
        return self.t.token_type == "symbol" and self.t.token_body == ")"
    def is_parens_start(self) -> bool:
        return self.t.token_type == "symbol" and self.t.token_body == "("
    
    def is_expr_end(self) -> bool:
        if self.t.token_type == "symbol":
            if self.t.token_body == "," or self.t.token_body == ")" or self.t.token_body == ";":
                return True
        return False

    def tab(self):
        self.prefix += 1

    def untab(self):
        self.prefix -= 1

    def pointer(self) -> int:
        return self.file_in.tell()

    def look_ahead(self) -> str:
        pointer = self.pointer()
        token = self.t.token
        self.set_token()
        new_token = self.t.token
        self.file_in.seek(pointer)
        self.t.set(token)
        self.count -= 1
        return new_token

