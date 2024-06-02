from Parser import (
    get_arithmetic_asm,
    get_compare_asm,
    get_boolean_asm,
    get_unary_asm,
    get_push_asm,
    get_pop_asm,
    push_to_stack_asm,
    pop_stack,
)

p = {
    "local": "LCL",
    "argument": "ARG",
    "this": "THIS",
    "that": "THAT",
    "pointer": "pointer",
    "constant": "constant",
    "temp": "temp",
    "static": "static",
}
T, F, L0, L1, L2 = [-1, 0, 13, 14, 15]


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


def write_push_pop(instruction, file_name):
    cmd, seg, i = instruction

    # push segment i
    if cmd == "push":
        return get_push_asm(p[seg], i, file_name)

    # pop segment i
    if cmd == "pop":
        return get_pop_asm(p[seg], i, file_name)

    raise Exception("Unrecogized command: {cmd}")


def write_init():
    return f"@256\nD=A\n{write_call("Sys.init", 0, "Sys.init$ret")}"


def write_label(label):
    return f"({label})\n"


def write_goto(label):
    return f"@{label}\n0;JMP\n"


def write_if_goto(label):
    return f"@SP\nAM=M-1\nD=M\n@{label}\nD;JNE\n"


def write_function(function_name, num_vars, count):
    output = ""
    # (functionName) -- delcares label for function entry
    output += f"({function_name})\n"
    # repeat nVars times: push 0
    # set nVars to temp
    output += f"@{num_vars}\nD=A\n@{L0}\nM=D // set nVars to temp\n"
    # Start loop and load temp var
    output += f"(LOOP{count})\n@{L0}\nD=M // start loop and load temp var\n"
    # Push 0 in loop
    output += f"@ENDLOOP{count}\nD;JEQ\n{get_push_asm('constant', 0, None)}@{L0}\nM=M-1\n@LOOP{count}\n0;JMP\n(ENDLOOP{count}) // push 0 in loop\n"
    return output


def write_call(function_name, num_args, caller_ret):
    output = ""
    # push return address
    output += f"@{caller_ret}\nD=A\n{push_to_stack_asm('push return address')}"
    # push LCL
    output += f"@LCL\nD=M\n{push_to_stack_asm('push LCL')}"
    # push ARG
    output += f"@ARG\nD=M\n{push_to_stack_asm('push ARG')}"
    # push THIS
    output += f"@THIS\nD=M\n{push_to_stack_asm('push THIS')}"
    # push THAT
    output += f"@THAT\nD=M\n{push_to_stack_asm('push THAT')}"
    # ARG = SP - 5 - nArgs
    output += (
        f"@{5 + num_args}\nD=A\n@SP\nD=M-D\n@ARG\nM=D  // ARG = SP - (5 + nArgs)\n"
    )
    # LCL = SP
    output += f"@SP\nD=M\n@LCL\nM=D  // LCL = SP\n"
    # goto functionName
    output += write_goto(function_name)
    # (returnAddress) --- declares a label for the return address ex. Foo$ret.1
    output += write_label(caller_ret)
    return output


def write_return():
    output = ""
    # endFrame = LCL -- this is a temp var
    output += f"@LCL\nD=M\n@{L0}\nM=D  // endFrame = LCL\n"
    # retAddr = *(endFrame - 5) -- this is a temp var
    output += f"@5\nA=D-A\nD=M\n@{L1}\nM=D  // returnAddr = *(endFrame-5)\n"
    # change *ARG = pop() --- poppping the return value into the address saved in ARG
    output += (
        f"{pop_stack()}@ARG\nA=M\nM=D  // pop return value into address saved in ARG\n"
    )
    # SP = ARG + 1
    output += f"@ARG\nD=M+1\n@SP\nM=D  // SP = ARG + 1\n"
    # THAT = *(endFrame - 1)
    output += f"@{L0}\nA=M-1\nD=M\n@THAT\nM=D  // THAT = *(endFrame - 1)\n"
    # THIS = *(endFrame - 2)
    output += f"@2\nD=A\n@{L0}\nA=M-D\nD=M\n@THIS\nM=D  // THIS = = *(endFrame - 2)\n"
    # ARG = *(endFrame - 3)
    output += f"@3\nD=A\n@{L0}\nA=M-D\nD=M\n@ARG\nM=D  // ARG = = *(endFrame - 3)\n"
    # LCL = *(endFrame - 4)
    output += f"@4\nD=A\n@{L0}\nA=M-D\nD=M\n@LCL\nM=D  // LCL = = *(endFrame - 4)\n"
    # goto retAddr
    output += f"@{L1}\nA=M\n0;JMP  // goto retAddr\n"
    return output
