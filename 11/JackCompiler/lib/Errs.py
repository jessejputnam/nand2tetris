def start_err(token: str):
    return f"encountered unexpected token while starting file compilation: {token}"


def bad_token(token: str):
    return f"Encountered incorrect token while compiling file: {token}"


def bad_class_token(token: str, count: int):
    return (
        f"Encountered unexpected token while compiling class at line {count} \n{token}"
    )


def bad_var_dec():
    return "Encountered incorrect token while compiling variable declaration"


def bad_sub_dec():
    return "encountered NULL while compiling subroutine declaration"


def bad_statement(token, count):
    return f"encountered unexpected token while compiling statements at line {count}\n{token}"
