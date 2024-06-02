import sys

from CodeWriter import (
    write_arithmetic,
    write_call,
    write_function,
    write_goto,
    write_if_goto,
    write_label,
    write_push_pop,
    write_return,
    write_init,
)
from Lib import check_args, get_program_and_files, clean_line

count = 0
output = write_init()

if __name__ == "__main__":
    try:
        check_args(sys.argv)
        program_name, files = get_program_and_files(sys.argv[1])

        for file in files:
            with open(file) as f:
                file_name = file.split("/")[-1][:-3]
                for line in f:
                    line = clean_line(line)
                    if not line:
                        continue

                    # Write comment
                    output += f"// ######### {line} ###########\n"
                    instr = line.split(" ")

                    if len(instr) == 1:
                        if instr[0] == "return":
                            output += write_return()
                        else:
                            output += write_arithmetic(instr[0], count)

                    elif instr[0] in ["push", "pop"]:
                        output += write_push_pop(instr, file_name)

                    elif instr[0] == "label":
                        output += write_label(instr[1])

                    elif instr[0] == "if-goto":
                        output += write_if_goto(instr[1])

                    elif instr[0] == "goto":
                        output += write_goto(instr[1])

                    elif instr[0] == "function":
                        output += write_function(instr[1], int(instr[2]), count)

                    elif instr[0] == "call":
                        ret_name = f"{file_name}_{instr[1]}$ret.{count}"
                        output += write_call(instr[1], int(instr[2]), ret_name)

                    count += 1

            # Write to file
            with open(f"{program_name}.asm", "w") as wf:
                wf.write(output)

        print("Assembly compiled")

    # Error Catching
    except FileNotFoundError:
        print("File not found or cannot be opened.")

    except IOError:
        print("An I/O error occurred while reading the file.")

    except Exception as e:
        print("An unexpected error occurred: vm instruction", count, " || ", e)
