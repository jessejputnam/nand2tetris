from JackTokenizer import JackTokenizer


class CompilationEngine:
    def __init__(self, input_path: str, output_path: str):
        self.token = None
        self.token_body = None
        self.token_type = None
        self.tokens = None
        self.output = None

        # self.compile_class()
        with open(input_path, "r") as self.tokens:
            with open(output_path, "w") as self.output:

                for token in self.tokens:
                    if token in ["<tokens>", "</tokens>"]:
                        continue
                    self.set_token(token)

                    if self.token_type == "keyword":
                        if self.token_body in ["var", "static"]:
                            self.write("<classVarDec>")
                            self.compile_class_var_dec()
                            self.write("</classVarDec>")

    def read_token(self):
        self.set_token(self.tokens.readLine())

        if self.token == "</tokens>":
            return

        if self.token_type == "tokens":
            return self.read_token()

        if self.token_type == "keyword":
            if self.token_body in ["static", "var"]:
                self.write("<classVarDec>")
                self.compile_class_var_dec()
                self.write("/<classVarDec>")

    def compile_class(self):
        # Compiles a complete class
        pass

    def compile_class_var_dec(self):
        # Compiles a static variable declaration or field declaration
        self.write(self.token)

    #    <classVarDec>
    #     <keyword> static </keyword>
    #     <keyword> boolean </keyword>
    #     <identifier> test </identifier>
    #     <symbol> ; </symbol>
    #   </classVarDec>

    # <keyword> static </keyword>
    # <keyword> boolean </keyword>
    # <identifier> test </identifier>
    # <symbol> ; </symbol>

    def compile_subroutine_dec(self):
        # Compiles a complete method, function, or constructor
        pass

    def compile_parameter_list(self):
        # Compiles a possibly empty parameter list. Does not handle enclosing "()"
        pass

    def compile_subroutine_body(self):
        # Compiles a subroutine's body
        pass

    def compile_var_dec(self):
        # Compiles a var declaration
        pass

    def compile_statements(self):
        # Compiles a sequence of statements. Does not handle the enclosing "{}"
        pass

    def compile_let(self):
        # Compiles a let statement
        self.write("<letStatement>")
        self.write(self.token)

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

    def write(self, token: str):
        self.output.write(f"{token}\n")

    def set_token(self, token: str):
        self.token = token
        self.token_type = token[1 : token.find(">")]
        self.token_body = token[token.find(">") + 2 : token.rfind("</") - 1]
