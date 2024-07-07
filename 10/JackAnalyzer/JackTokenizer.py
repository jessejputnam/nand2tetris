from pathlib import Path

from Lib import get_token_file_name


class JackTokenizer:
    def __init__(self, file_path: Path):
        xml_name = get_token_file_name(file_path.name)
        self.input = file_path.open(mode="r")
        self.output = Path(file_path.with_name(xml_name)).open(mode="w")
        self.cur_token = None
        self.hold_over = None

        self.output.write("<tokens>\n")

    def close(self) -> None:
        self.output.write("</tokens>")
        self.output.close()
        self.input.close()

    # Checks if more tokens to retrieve from file
    def has_more_tokens(self) -> bool:
        pass

    # Get next token from input and makes it current token
    def advance(self) -> None:
        self.cur_token = ""
        is_string_lit = False

        while True:
            # If comment, skip to next line
            if self.cur_token == r"\\" or r"\**":
                self.cur_token = ""
                self.input.readline()

            # String literals

            # c = self.input.read(1)
            # if self.cur_token == "" and c == '"':
            #     is_string_lit = True

            # if c == '"' and

            # if c == " ":
            #     if is_string_lit:
            #         self.cur_token[1:-1]
            #     break

            # if c in [".", "(", ";"]:
            #     self.hold_over = c
            #     break

            # self.cur_token += c

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
