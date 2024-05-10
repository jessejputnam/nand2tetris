import sys

from CodeWriter import write_arithmetic

from Parser import (
    get_arithmetic_asm,
    get_compare_asm,
    get_boolean_asm,
    get_unary_asm,
    get_pop_asm,
    get_push_asm,
)

p = {"local": "LCL", "argument": "ARG", "this": "THIS", "that": "THAT"}
count = 0

output = ""

try:
    args = sys.argv

    if len(args) == 1:
        raise Exception("No file specified")

    if len(args) > 2:
        raise Exception("Too many command line args")

    file = args[1]
    file_name = file[:-3]
    file_ext = file[-3:]

    if not file_ext == ".vm":
        raise Exception("Unrecognized file type -- Requires .vm extension")

    with open(file) as f:
        for line in f:
            trimmed = line.strip()
            if not trimmed or trimmed[:2] == "//":
                continue

            # Output comment
            output += f"// {trimmed}\n"
            instruction = trimmed.split(" ")

            # Arithmetic / Logical Commands
            if len(instruction) == 1:
                cmd = instruction[0]
                # add, sub
                if cmd in ["add", "sub"]:
                    output += get_arithmetic_asm(cmd)

                # eq, lt, gt
                elif cmd in ["eq", "gt", "lt"]:
                    output += get_compare_asm(cmd, count)

                # and, or
                elif cmd in ["and", "or"]:
                    output += get_boolean_asm(cmd)

                # neg
                elif cmd in ["not", "neg"]:
                    output += get_unary_asm(cmd)

                else:
                    raise Exception(f"Unrecognized command: {cmd}")

            # # Memory Segment Commands
            else:
                # push segment i
                cmd, seg, i = instruction
                if cmd == "push":
                    output += get_push_asm(seg, i, p)

                # pop segment i
                elif cmd == "pop":
                    output += get_pop_asm(seg, i, p)

                else:
                    raise Exception("Unrecogized command: {cmd}")

            count += 1

    output += "(ENDPROGRAM)\n@ENDPROGRAM\n0;JMP\n"

    # Write to file
    with open(f"{file_name}.asm", "w") as wf:
        wf.write(output)

    print("Assembly compiled")

# Error Catching
except FileNotFoundError:
    print("File not found or cannot be opened.")

except IOError:
    print("An I/O error occurred while reading the file.")

except Exception as e:
    print("An unexpected error occurred:", e)
