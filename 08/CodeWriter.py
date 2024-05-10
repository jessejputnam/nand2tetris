from Parser import (
    get_arithmetic_asm,
    get_compare_asm,
    get_boolean_asm,
    get_unary_asm,
    get_push_asm,
    get_pop_asm,
)

p = {"local": "LCL", "argument": "ARG", "this": "THIS", "that": "THAT"}


def write_arithmetic(cmd, file_name, count):
    # add, sub
    if cmd in ["add", "sub"]:
        return get_arithmetic_asm(cmd)

    # eq, lt, gt
    if cmd in ["eq", "gt", "lt"]:
        return get_compare_asm(cmd, file_name, count)

    # and, or
    if cmd in ["and", "or"]:
        return get_boolean_asm(cmd)

    # neg
    if cmd in ["not", "neg"]:
        return get_unary_asm(cmd)

    raise Exception(f"Unrecognized command: {cmd}")


def write_push_pop(instruction, file_name):
    cmd, seg, i = instruction

    # push segment i
    if cmd == "push":
        return get_push_asm(seg, i, p)

    # pop segment i
    if cmd == "pop":
        return get_pop_asm(seg, i, p)

    raise Exception("Unrecogized command: {cmd}")


def write_init():
    pass


def write_label(label, file_name):
    return f"({file_name}.{label})\n"


def write_goto(label, file_name):
    return f"@{file_name}.{label}\n0;JMP\n"


def write_if_goto(label, file_name):
    return f"@SP\nAM=M-1\nD=M\n@{file_name}.{label}\nD;JNE\n"


def write_function(function_name, file_name, num_vars):
    pass


def write_call(function_name, file_name, num_args):
    pass


def write_return():
    pass
