from pathlib import Path

from Lib import get_token_file_name


class JackTokenizer:
    def __init__(self, file_path: Path):
        xml_name = get_token_file_name(file_path.name)
        self.input = file_path.open(mode="r")
        self.output = Path(file_path.with_name(xml_name)).open(mode="w")
        self.cur_token = None
        self.output.write("<tokens>\n")

    def close(self) -> None:
        self.output.write("</tokens>")
        self.output.close()
        self.input.close()

    def has_more_tokens(self) -> bool:
        # Checks if more tokens to retrieve from file
        pass

    def advance(self) -> None:
        # Get next token from input and makes it current token
        pass

    def token_type(self) -> str:
        # Returns the type of the current token
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
