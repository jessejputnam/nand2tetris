import sys

from CodeWriter import (
    write_arithmetic,
    write_goto,
    write_if_goto,
    write_label,
    write_push_pop,
)
from Lib import check_args, get_program_and_files, end_program, clean_line

count = 0
output = ""

if __name__ == "__main__":
    try:
        check_args(sys.argv)
        program_name, files = get_program_and_files(sys.argv[1])
        print(f"check {files}")

        for file in files:
            with open(file) as f:
                file_name = file.split("/")[-1][:-3]

                for line in f:
                    line = clean_line(line)
                    if not line:
                        continue

                    # Write comment
                    output += f"// {line}\n"
                    instr = line.split(" ")

                    if len(instr) == 1:
                        output += write_arithmetic(instr[0], file_name, count)

                    elif instr[0] in ["push", "pop"]:
                        output += write_push_pop(instr, file_name)

                    elif instr[0] == "label":
                        output += write_label(instr[1], file_name)

                    elif instr[0] == "if-goto":
                        output += write_if_goto(instr[1], file_name)

                    elif instr[0] == "goto":
                        output += write_goto(instr[1], file_name)

                    count += 1

            output += end_program()

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
        print("An unexpected error occurred:", e)
