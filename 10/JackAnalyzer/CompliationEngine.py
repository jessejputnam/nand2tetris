from JackTokenizer import JackTokenizer


class CompilationEngine:
    def __init__(self, input_path: str, output_path: str):
        self.token = None
        self.token_body = None
        self.token_type = None
        self.file_in = None
        self.file_out = None

        with open(input_path, "r") as self.file_in:
            with open(output_path, "w+") as self.file_out:
                self.set_token()

                while self.token != "</tokens>":
                    self.set_token()
                    if self.is_class_dec():
                        self.compile_class()
                    # elif self.is_subroutine():
                    #     self.compile_subroutine_dec()

    def compile_class(self):
        # Compiles a complete class
        self.write("<class>")
        self.write()

        while True:
            if self.is_block_end():
                break
            self.set_token()
            if self.token_type == "keyword":
                # classVarDec
                if self.token_body in ["static", "field"]:
                    self.compile_class_var_dec()

            else:
                self.write(self.token)
        self.write("</class>")

    def compile_class_var_dec(self):
        # Compiles a static variable declaration or field declaration
        self.write("<classVarDec>")
        self.write()
        while True:
            if self.is_statement_end():
                break
            self.set_token()
            self.write()
        self.write("</class>")

    def compile_subroutine_dec(self):
        # Compiles a complete method, function, or constructor
        self.write("<subroutineDec>")
        self.write()
        while True:
            if self.is_block_end():
                break
            self.set_token()
            if self.token_type == "symbol":
                if self.token_body == "(":
                    self.compile_parameter_list()
                elif self.token_body == "{":
                    self.compile_subroutine_body()
            else:
                self.write()

    def compile_parameter_list(self):
        # Compiles a possibly empty parameter list. Does not handle enclosing "()"
        self.write()
        self.write("<parameterList>")
        while True:
            self.set_token()
            if self.token_type == "symbol" and self.token_body == ")":
                break
            self.write()
        self.write("</parameterList>")
        self.write()

    def compile_subroutine_body(self):
        # Compiles a subroutine's body
        self.write("<subroutineBody>")
        #####################################################
        #####################################################
        #####################################################
        #####################################################
        ############  STOPPED HEREER #######################
        #####################################################
        #####################################################
        #####################################################
        self.write("</subroutineBody>")

    def compile_var_dec(self):
        # Compiles a var declaration
        pass

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        pass

    def compile_let(self):
        # Compiles a let statement
        self.write("<letStatement>")
        self.write()

    def compile_if(self):
        # Compiles an if statement, possibly with a trailing else clause
        pass

    def compile_while(self):
        # Compiles a while statement
        pass

    def compile_do(self):
        # Compiles a do statement
        pass

    def compile_return(self):
        # Compiles a return statement
        pass

    def compile_expression(self):
        # Compiles an esxpression
        pass

    def compile_term(self):
        # Compiles a term.
        # If the current token is an identifier, routine must distinguish between:
        #   - a variable, an array entry, or a subroutine call.
        # A single look-ahead token, which may be [, (, or . suffices to distiguish
        # Any other is not a part of this term and should be advanced over
        pass

    def compile_expression_list(self):
        # Compiles a possibly empty comma-separated list of expressions
        pass

    def write(self, token: str = None):
        self.file_out.write(f"{token or self.token}\n")

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
        self.token_type == "symbol" and self.token_body == "}"
