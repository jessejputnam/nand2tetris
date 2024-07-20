from JackTokenizer import JackTokenizer


class CompilationEngine:
    def __init__(self, input_path: str, output_path: str):
        self.token = None
        self.token_body = None
        self.token_type = None
        self.file_in = None
        self.file_out = None
        self.prefix = 0

        with open(input_path, "r") as self.file_in:
            with open(output_path, "w+") as self.file_out:
                self.set_token()

                while self.token != "</tokens>":
                    self.set_token()
                    if self.is_class_dec():
                        self.compile_class()

    def compile_class(self):
        # Compiles a complete class
        self.write("<class>")
        self.write()

        while True:
            self.set_token()

            if self.is_block_end():
                break

            if self.token_type == "keyword":
                # classVarDec
                if self.token_body in ["static", "field"]:
                    self.compile_class_var_dec()
                    continue
                # subroutine
                if self.is_subroutine():
                    self.compile_subroutine_dec()
                    continue

            self.write()
        self.write()
        self.write("</class>")

    def compile_class_var_dec(self):
        # Compiles a static variable declaration or field declaration
        self.write("<classVarDec>")
        self.write()
        while True:
            self.set_token()
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
            if self.is_block_end():
                break

            if self.token_type == "symbol":
                if self.token_body == "(":
                    self.compile_parameter_list()
                    continue
                if self.token_body == "{":
                    self.compile_subroutine_body()
                    self.set_token()
                    break
            self.write()
        self.write()
        self.write("</subroutineDec>")

    def compile_parameter_list(self):
        # Compiles a possibly empty parameter list. Does not handle enclosing "()"
        self.write()
        self.write("<parameterList>")
        while True:
            self.set_token()
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

            if self.token_type == "keyword" and self.token_body == "var":
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
            if self.is_statement_end():
                break
            self.write()
        self.write()
        self.write("</varDec>")

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        self.write("<statements>")
        

        while True:
            if self.is_block_end():
                break

            if self.token_type == "keyword" and self.token_body == "let":
                self.compile_let()
            elif self.token_type == "keyword" and self.token_body == "if":
                self.compile_if()
            elif self.token_type == "keyword" and self.token_body == "while":
                self.compile_while()
            elif self.token_type == "keyword" and self.token_body == "do":
                self.compile_do()
            elif self.token_type == "keyword" and self.token_body == "return":
                self.compile_return()
                break

            self.set_token()
        self.write("</statements>")

    def compile_let(self):
        # Compiles a let statement
        self.write("<letStatement>")
        self.write()
        while True:
            self.set_token()

            if self.token_type == "symbol" and self.token_body == "=":
                self.write()
                self.compile_expression()
                break
            self.write()

        self.write()
        self.write("</letStatement>")

    def compile_if(self):
        # Compiles an if statement, possibly with a trailing else clause
        pass

    def compile_while(self):
        # Compiles a while statement
        pass

    def compile_do(self):
        # Compiles a do statement
        self.write("<doStatement>")
        self.write()
        while True:
            self.set_token()

            if self.is_statement_end():
                break
            elif self.token_type == "symbol" and self.token_body == "(":
                self.compile_expression_list()
            else:
                self.write()

        self.write()
        self.write("</doStatement>")

    def compile_return(self):
        # Compiles a return statement
        self.write("<returnStatement>")
        self.write()
        while True:
            self.set_token()
            if self.is_statement_end():
                break
            self.write()

        self.write()
        self.write("</returnStatement>")

    def compile_expression(self):
        # Compiles an expression
        self.write("<expression>")
        while True:
            self.set_token()
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
        while True:
            self.set_token()
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
            self.file_out.write(f"{"  "*self.prefix}{self.token}\n")
        else: 
            if token[1] == "/":
                self.untab()
                self.file_out.write(f"{"  "*self.prefix}{token}\n")
            else:
                self.file_out.write(f"{"  "*self.prefix}{token}\n")
                self.tab()

    def set_token(self):
        self.token = self.file_in.readline().strip()
        self.token_type = self.token[1 : self.token.find(">")]
        self.token_body = self.token[
            self.token.find(">") + 2 : self.token.rfind("</") - 1
        ]

    def is_class_dec(self):
        return self.token_type == "keyword" and self.token_body == "class"

    def is_subroutine(self):
        return self.token_type == "keyword" and self.token_body in [
            "method",
            "function",
            "constructor",
        ]

    def is_statement_end(self):
        return self.token_type == "symbol" and self.token_body == ";"

    def is_block_end(self):
        return self.token_type == "symbol" and self.token_body == "}"

    def is_parens_end(self):
        return self.token_type == "symbol" and self.token_body == ")"
    
    def is_expr_end(self):
        if self.token_type == "symbol":
            if self.token_body == "," or self.token_body == ")" or self.token_body == ";":
                return True
        return False

    def tab(self):
        self.prefix += 1

    def untab(self):
        self.prefix -= 1
