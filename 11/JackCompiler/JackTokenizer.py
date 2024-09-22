from pathlib import Path

from lib.Lib import (
    get_token_file_name,
    is_symbol,
    is_int,
    is_keyword,
    sanitize,
)


class JackTokenizer:
    def __init__(self, file_path: Path):
        xml_name = get_token_file_name(file_path.name)
        self.input = file_path.open(mode="r")
        self.output = Path(file_path.with_name(xml_name)).open(mode="w+")
        self.cur_token = None
        self.end = None
        self.set_file_end()

        self.output.write("<tokens>\n")

    def get_tell(self):
        return self.input.tell()

    def test_goto(self, tell: int):
        self.input.seek(tell)

    def test_get_char(self):
        return self.input.read(1)

    def test_tells(self):
        for i in range(self.end):
            self.input.read(1)
            print(self.get_tell())

    def test_read(self):
        self.input.read()

    def test(self):
        print(f"tell: {self.get_tell()}   end: {self.end}")

    def close(self) -> None:
        self.output.write("</tokens>")
        self.output.close()
        self.input.close()

    # Checks if more tokens to retrieve from file
    def has_more_tokens(self) -> bool:
        return self.get_tell() != self.end

    # Get next token from input and makes it current token
    def advance(self) -> None:
        token = ""
        is_string_lit = False

        while True:
            tell = self.get_tell()
            c = self.input.read(1)

            # Move forward if no token and char is whitespace and not string lit
            if c.isspace() and not is_string_lit and token == "":
                continue

            # String literal
            elif c == '"':
                token += c
                if not is_string_lit:
                    is_string_lit = True
                else:
                    self.cur_token = token
                    return

            # stop advancing on space, store token
            elif c.isspace() and not is_string_lit:
                self.cur_token = token
                return

            # symbol encountered
            elif is_symbol(c):
                # symbol encountered while building token
                if token != "":
                    self.cur_token = token
                    self.input.seek(tell)
                    return

                # potential comment
                if c == "/":
                    c2 = self.input.read(1)
                    if c2 == "/":
                        self.input.readline()
                        continue
                    if c2 == "*":
                        l = self.input.readline().strip()
                        while l[-2:] != "*/":
                            l = self.input.readline().strip()
                        continue

                    if c2 in "/*":
                        # comment
                        self.input.readline()
                        continue
                    else:
                        # not comment, go back
                        self.input.seek(tell + 1)

                # symbol encountered alone
                self.cur_token = c
                return

            # add character to currently building token
            else:
                token += c

    def check_token(self):
        return self.cur_token

    def write_token(self):
        token_type = self.token_type()
        if token_type == "KEYWORD":
            self.output.write(self.key_word() + "\n")
        elif token_type == "SYMBOL":
            self.output.write(self.symbol() + "\n")
        elif token_type == "INT_CONST":
            self.output.write(self.int_val() + "\n")
        elif token_type == "STRING_CONST":
            self.output.write(self.str_val() + "\n")
        elif token_type == "IDENTIFIER":
            self.output.write(self.identifier() + "\n")

    # Returns the type of the current token
    def token_type(self) -> str:
        if self.cur_token == "":
            return ""
        if self.cur_token[0] == '"':
            return "STRING_CONST"
        if is_symbol(self.cur_token):
            return "SYMBOL"
        if is_keyword(self.cur_token):
            return "KEYWORD"
        if is_int(self.cur_token[0]):
            return "INT_CONST"
        return "IDENTIFIER"

    def key_word(self) -> str:
        # Returns the key word which is the current token
        # Can only be called if token_type is KEYWORD
        return f"<keyword> {self.cur_token} </keyword>"

    def symbol(self) -> str:
        # Returns the character which is the current token
        # Can only be called if token_type is SYMBOL
        return f"<symbol> {sanitize(self.cur_token)} </symbol>"

    def identifier(self) -> str:
        # Returns the identifier which is the current token
        # Can only be called if token_type is IDENTIFIER
        return f"<identifier> {self.cur_token} </identifier>"

    def int_val(self) -> str:
        # Returns the integer value which is the current token
        # Can only be called if token_type is INT_CONST
        return f"<integerConstant> {self.cur_token} </integerConstant>"

    def str_val(self) -> str:
        # Returns the string value which is the current token without the enclosing double quotes
        # Can only be called if token_type is STRING_CONST
        return f"<stringConstant> {self.cur_token[1:-1]} </stringConstant>"

    def set_file_end(self):
        self.input.seek(0, 2)
        end = self.input.tell()
        self.input.seek(0)
        self.end = end
