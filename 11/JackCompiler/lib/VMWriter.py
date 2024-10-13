from typing import Literal
from lib.Funcs import get_seg

seg_type = Literal["CONST", "ARG", "LOCAL", "STATIC", "THIS", "THAT", "POINTER", "TEMP"]
comm_type = Literal["ADD", "SUB", "NEG", "EQ", "GT", "LT", "AND", "OR", "NOT"]


class VMWriter:
    def __init__(self, output):
        # Creates new output .vm file and prepares it for writing
        self.output = open(f"{output}", "w")
        program_name = str(output).split("/")[-2]
        self.output.write(f"// VM Code for program: {program_name}\n")

    def write_push(self, segment: seg_type, index: int):
        # Writes a VM push command
        self.output.write(f"\tpush {get_seg(segment)} {index}\n")

    def write_pop(self, segment: seg_type, index: int):
        # Writes a VM pop command
        self.output.write(f"\tpop {get_seg(segment)} {index}\n")

    def write_arithmetic(self, command: comm_type):
        # Writes a VM arithemtic-logical command
        self.output.write(f"\t{command.lower()}\n")

    def write_label(self, label: str):
        # Writes a VM label command
        self.output.write(f"label {label}\n")

    def write_goto(self, label: str):
        # Writes a VM goto command
        self.output.write(f"\tgoto {label}\n")

    def write_if(self, label: str):
        # Writes a VM if-goto command
        self.output.write(f"\tif-goto {label}\n")

    def write_call(self, name: str, n_args: int):
        # Writes a VM call command
        self.output.write(f"\tcall {name} {n_args}\n")

    def write_function(self, name: str, n_locals: int):
        # Writes a VM function command
        self.output.write(f"\nfunction {name} {n_locals}\n")

    def write_return(self):
        # Writes a VM return command
        self.output.write("\treturn\n")

    def close(self):
        # Closes the output file
        self.output.close()
