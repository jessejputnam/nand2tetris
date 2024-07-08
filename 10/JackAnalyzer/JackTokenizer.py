from pathlib import Path

from Lib import get_token_file_name, is_symbol


class JackTokenizer:
    def __init__(self, file_path: Path):
        xml_name = get_token_file_name(file_path.name)
        self.input = file_path.open(mode="r")
        self.output = Path(file_path.with_name(xml_name)).open(mode="w")
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
            c = self.input.read(1)

            # Move forward if no token and char is whitespace
            if token == "" and c.isspace():
                continue

            # If start of string literal
            elif token == "" and c == '"':
                is_string_lit = True

            # stop advancing on space, store token
            elif c.isspace():
                self.cur_token = token
                return

            elif is_symbol(c):
                tell = self.input.tell()

                if token != "":
                    self.cur_token = token
                    self.input.seek(tell - 1)
                    return

                if c == "/":
                    c2 = self.input.read(1)
                    if c2 in "/*":
                        # Comment
                        self.input.readline()
                        continue
                    else:
                        # Legit symbol
                        self.input.seek(tell)
                self.cur_token = c
                return

            # add character to currently building token
            else:
                token += c

    def check_token(self):
        return self.cur_token

    # Returns the type of the current token
    def token_type(self) -> str:
        pass

    def key_word(self) -> str:
        # Returns the key word which is the current token
        # Can only be called if token_type is KEYWORD
        pass

    def symbol(self) -> str:
        # Returns the character which is the current token
        # Can only be called if token_type is SYMBOL
        pass

    def identifier(self) -> str:
        # Returns the identifier which is the current token
        # Can only be called if token_type is IDENTIFIER
        pass

    def int_val(self) -> str:
        # Returns the integer value which is the current token
        # Can only be called if token_type is INT_CONST
        pass

    def str_val(self) -> str:
        # Returns the string value which is the current token without the enclosing double quotes
        # Can only be called if token_type is STRING_CONST
        pass

    def set_file_end(self):
        self.input.seek(0, 2)
        end = self.input.tell()
        self.input.seek(0)
        self.end = end
