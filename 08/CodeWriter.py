from Parser import (
    get_arithmetic_asm,
    get_compare_asm,
    get_boolean_asm,
    get_unary_asm,
    get_push_asm,
    get_pop_asm,
)

p = {"local": "LCL", "argument": "ARG", "this": "THIS", "that": "THAT"}


def write_arithmetic(cmd, count):
    # add, sub
    if cmd in ["add", "sub"]:
        return get_arithmetic_asm(cmd)

    # eq, lt, gt
    if cmd in ["eq", "gt", "lt"]:
        return get_compare_asm(cmd, count)

    # and, or
    if cmd in ["and", "or"]:
        return get_boolean_asm(cmd)

    # neg
    if cmd in ["not", "neg"]:
        return get_unary_asm(cmd)

    raise Exception(f"Unrecognized command: {cmd}")


def write_push_pop(instruction):
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


def write_label(label):
    return f"({label})\n"


def write_goto(label):
    return f"@{label}\n0;JMP\n"


def write_if_goto(label):
    return f"@SP\nAM=M-1\nD=M\n@{label}\nD;JNE\n"


def write_call(function_name, num_args):
    ### Handles call functionName nArgs
    # push return address
    # push LCL
    # push ARG
    # push THIS
    # push THAT
    # ARG = SP - 5 - nArgs
    # LCL = SP
    # goto functionName
    # (returnAddress) --- declares a label for the return address ex. Foo$ret.1
    pass


def write_function(function_name, num_vars):
    # (functionName) -- delcares lavel for function entry
    # repeat nVars times: push 0
    pass


def write_return():
    # endFrame = LCL -- this is a temp variable
    # retAddr = *(endFrame - 5)
    # *ARG = pop() --- poppping the return value into the address saved in ARG
    # SP = ARG + 1
    # THAT = *(endFrame - 1)
    # THIS = *(endFrame - 2)
    # ARG = *(endFrame - 3)
    # LCL = *(endFrame - 4)
    # goto retAddr
    pass
