from pathlib import Path


def check_args(args) -> None:
    if len(args) == 1:
        raise Exception("No file specified")
    if len(args) > 2:
        raise Exception("Too many command line args")


def get_files_list(arg: str) -> list[Path]:
    path = Path(arg)

    if path.is_file():
        if path.suffix == ".jack":
            files = [path]

    if path.is_dir():
        files = [file for file in path.iterdir() if is_jack_file(file)]

    if len(files) == 0:
        raise Exception("No Jack files found from argument path.")
    return files


def is_jack_file(file: Path):
    return file.is_file() and file.suffix == ".jack"


def get_token_file_name(file_name: str):
    return f"{file_name[:-5]}T.xml"


def get_parsed_file_name(file_name: str):
    return f"{file_name[:-5]}.xml"


def is_symbol(char: str):
    return char in "{}()[].,;+-*/&|><=~"


def is_int(char: str):
    return char in "0123456789"


def is_keyword(token: str):
    return token in [
        "class",
        "constructor",
        "function",
        "method",
        "field",
        "static",
        "var",
        "int",
        "char",
        "boolean",
        "void",
        "true",
        "false",
        "null",
        "this",
        "let",
        "do",
        "if",
        "else",
        "while",
        "return",
    ]


def sanitize(c: str) -> str:
    match c:
        case "<":
            return "&lt;"
        case ">":
            return "&gt;"
        case "&":
            return "&amp;"
        case _:
            return c


def safe_true(count: int) -> bool:
    if count > 5000:
        raise Exception("Compiler hit an infinite loop")
    return True
