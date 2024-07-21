class Token:
    def set(self, token: str):
        self.token = token
        self.token_type = self.token[1 : self.token.find(">")]
        self.token_body = self.token[
            self.token.find(">") + 2 : self.token.rfind("</") - 1
        ]
