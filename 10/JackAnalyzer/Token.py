class Token:
    def __init__(self, token: str = None):
        self.token = token
        self.token_type = (
            None if token is None else self.token[1 : self.token.find(">")]
        )
        self.token_body = (
            None
            if token is None
            else self.token[self.token.find(">") + 2 : self.token.rfind("</") - 1]
        )

    def set(self, token: str):
        self.token = token
        self.token_type = self.token[1 : self.token.find(">")]
        self.token_body = self.token[
            self.token.find(">") + 2 : self.token.rfind("</") - 1
        ]

    def is_class_dec(self) -> bool:
        return self.token_type == "keyword" and self.token_body == "class"

    def is_subroutine(self) -> bool:
        return self.token_type == "keyword" and self.token_body in [
            "method",
            "function",
            "constructor",
        ]

    def is_expr_end(self) -> bool:
        if self.token_type == "symbol":
            if self.token_body in [",", ")", ";", ",", "]"]:
                return True
        return False

    def is_statement_end(self) -> bool:
        return self.token_type == "symbol" and self.token_body == ";"

    def is_block_end(self) -> bool:
        return self.token_type == "symbol" and self.token_body == "}"

    def is_block_start(self) -> bool:
        return self.token_type == "symbol" and self.token_body == "{"

    def is_parens_end(self) -> bool:
        return self.token_type == "symbol" and self.token_body == ")"

    def is_parens_start(self) -> bool:
        return self.token_type == "symbol" and self.token_body == "("

    def is_arr_start(self) -> bool:
        return self.token_type == "symbol" and self.token_body == "["

    def is_dot(self) -> bool:
        return self.token_type == "symbol" and self.token_body == "."

    def is_unary_op(self) -> bool:
        return self.token_type == "symbol" and self.token_body in ["-", "~"]

    def is_op(self) -> bool:
        return self.token_type == "symbol" and self.token_body in [
            "+",
            "-",
            "*",
            "/",
            "&",
            "|",
            "&lt;",
            "&gt;",
            "=",
        ]

    def is_keyword_const(self) -> bool:
        return self.token_type == "keyword" and self.token_body in [
            "true",
            "false",
            "null",
            "this",
        ]
