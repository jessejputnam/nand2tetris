from typing import Literal

seg_type = Literal["CONST", "ARG", "LOCAL", "STATIC", "THIS", "THAT", "POINTER", "TEMP"]
comm_type = Literal["ADD", "SUB", "NEG", "EQ", "GT", "LT", "AND", "OR", "NOT"]


class VMWriter:
    def __init__(self, output):
        # Creates new output .vm file and prepares it for writing
        self.output = open(f"{output}", "w")
        self.output.write(f"// VM Code for {output} program\n\n")

    def write_push(self, segment: seg_type, index: int):
        # Writes a VM push command
        seg = (
            "constant"
            if segment == "CONST"
            else "argument" if segment == "ARG" else segment.lower()
        )
        self.output.write(f"push {seg} {index}\n")

    def write_pop(self, segment: seg_type, index: int):
        # Writes a VM pop command
        pass

    def write_arithmetic(self, command: comm_type):
        # Writes a VM arithemtic-logical command
        self.output.write(command.lower())

    def write_label(self, label: str):
        # Writes a VM label command
        pass

    def write_goto(self, label: str):
        # Writes a VM goto command
        pass

    def write_if(self, label: str):
        # Writes a VM if-goto command
        pass

    def write_call(self, name: str, n_args: int):
        # Writes a VM call command
        self.output.write(f"{name} {n_args}\n")

    def write_function(self, name: str, n_locals: int):
        # Writes a VM function command
        self.output.write(f"function {name} {n_locals}\n")

    def write_return(self):
        # Writes a VM return command
        pass

    def close(self):
        # Closes the output file
        self.output.close()
