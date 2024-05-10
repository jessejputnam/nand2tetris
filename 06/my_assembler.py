import sys

#############################################
############## HELPER FUNCTIONS #############
#############################################


def clean_line(line):
    # Remove Whitespace and comments
    trimmed = line.strip()
    return None if trimmed[:2] == "//" else trimmed


def init_symbol_table():
    return {
        "R0": 0,
        "R1": 1,
        "R2": 2,
        "R3": 3,
        "R4": 4,
        "R5": 5,
        "R6": 6,
        "R7": 7,
        "R8": 8,
        "R9": 9,
        "R10": 10,
        "R11": 11,
        "R12": 12,
        "R13": 13,
        "R14": 14,
        "R15": 15,
        "SCREEN": 16384,
        "KBO": 24576,
        "SP": 0,
        "LCL": 1,
        "ARG": 2,
        "THIS": 3,
        "THAT": 4,
    }


def to_binary(num):
    output = ""
    num = int(num)
    while num > 0:
        output = f"{num % 2}{output}"
        num = num // 2
    return output.zfill(15)


def a_instruction(line):
    num = line[1:]
    return f"0{to_binary(num)}"


def get_dest_and_cmd(line):
    dest_split = line.split("=")
    dest = "" if len(dest_split) == 1 else dest_split[0]

    has_dest = len(dest_split) > 1
    command = dest_split[1 if has_dest else 0]

    return [dest, command]


def convert_dest(dest):
    d = 0

    if "A" in dest:
        d += 100
    if "D" in dest:
        d += 10
    if "M" in dest:
        d += 1

    return str(d).zfill(3)


def get_comp_and_jmp(cmd):
    cmd_split = cmd.split(";")
    return [cmd_split[0], "" if len(cmd_split) == 1 else cmd_split[1]]


def convert_comp(comp):
    h = {
        "0": "101010",
        "1": "111111",
        "-1": "111010",
        "D": "001100",
        "A": "110000",
        "!D": "001101",
        "!A": "110001",
        "-D": "001111",
        "-A": "110011",
        "D+1": "011111",
        "A+1": "110111",
        "D-1": "001110",
        "A-1": "110010",
        "D+A": "000010",
        "D-A": "010011",
        "A-D": "000111",
        "D&A": "000000",
        "D|A": "010101",
    }
    comp = comp.replace("M", "A")
    return h[comp]


def convert_jump(jmp):
    j = 0

    if jmp in ["JLT", "JNE", "JLE", "JMP"]:
        j += 100
    if jmp in ["JEQ", "JGE", "JLE", "JMP"]:
        j += 10
    if jmp in ["JGT", "JGE", "JNE", "JMP"]:
        j += 1

    return str(j).zfill(3)


def convert_instruction(line):
    if line[0] == "@":  # A Command
        return a_instruction(line)
    else:  # C Command
        prefix = "111"
        dest, cmd = get_dest_and_cmd(line)
        comp, jump = get_comp_and_jmp(cmd)

        a = "1" if "M" in comp else "0"
        d = convert_dest(dest)
        c = convert_comp(comp)
        j = convert_jump(jump)
        return f"{prefix}{a}{c}{d}{j}"


#############################################
################ MAIN FUNCTION ##############
#############################################


def run_assembler(args):
    if len(args) == 1:
        print("Error: no file specified.")
        return

    if len(args) > 2:
        print("Error: too many args. Only specify file.")
        return

    if not args[1][-4:] == ".asm":
        print("Error: wrong file extension. Use .asm file.")
        return

    file_name = args[1].split("/")[-1].split(".")[0] + ".hack"

    output_file = ""

    symbol_table = init_symbol_table()
    try:
        file = open(args[1])
        # First Pass - LABELS
        line_count = 0
        for line in file:
            line = clean_line(line)
            if not line:
                continue

            if line[0] == "(":
                k = line[1:-1]
                symbol_table[k] = line_count
                continue

            line_count += 1

        # Second Pass - VARIABLES
        var_idx = 16

        file.close()
        file = open(args[1])

        # Translation Pass
        for line in file:
            line = clean_line(line)
            if not line:
                continue

            # Ignore Lables
            if line[0] == "(":
                continue

            # Convert Variables
            a, b = line[0], line[1:]
            if a == "@":
                if not b.isdigit():
                    if b not in symbol_table:
                        symbol_table[b] = var_idx
                        var_idx += 1
                    line = f"@{symbol_table[b]}"

            # Convert Instruction
            output = convert_instruction(line)
            output_file += output + "\n"
        file.close()

        with open(file_name, "w") as o:
            o.write(output_file)
        print("Binary successfully assembled")

    except Exception as e:
        print(f"Error: {e}")


#############################################
############## RUN MAIN FUNCTION ############
#############################################

run_assembler(sys.argv)
