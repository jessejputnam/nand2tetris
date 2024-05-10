t = -1
f = 0

def pop_stack():
    return f'@SP\nAM=M-1\nD=M\n'

# LOGIC COMMANDS
def get_arithmetic_asm(cmd):
    op = 'D+M' if cmd == 'add' else 'M-D'
    return f'{pop_stack()}A=A-1\nM={op}\n'

def get_boolean_asm(cmd):
    op = 'D&M' if cmd == 'and' else 'D|M'
    return f'{pop_stack()}A=A-1\nM={op}\n' 

def get_compare_asm(cmd, count):
    op = cmd.upper()
    return f'{pop_stack()}A=A-1\nD=M-D\n@IS{op}{count}\nD;J{op}\n@SP\nA=M-1\nM={f}\n@END{count}\n0;JMP\n(IS{op}{count})\n@SP\nA=M-1\nM={t}\n(END{count})\n'

def get_unary_asm(cmd):
    op = '!M' if cmd == 'not' else '-M'
    return f'@SP\nA=M-1\nM={op}\n'

# MEMORY COMMANDS

## Push
def get_mem_val_asm(seg, i, p):
    if seg == 'constant':
        return f'@{i}\nD=A\n'
    if seg == 'pointer':
        return f'@{'THIS' if i == '0' else 'THAT'}\nD=M\n'
    if seg == 'static':
        return f'@Foo.{i}\nD=M\n'
    return f'@{p[seg]}\nD=M\n@{i}\nA=A+D\nD=M\n'

def push_to_stack_asm():
    return f'@SP\nA=M\nM=D\n@SP\nM=M+1\n'

def get_push_asm(seg, i, p):
    return f"{get_mem_val_asm(seg, i, p)}{push_to_stack_asm()}"

## Pop
def push_to_mem_asm(seg, i):
    if seg == 'pointer':
        pointer = 'THIS' if i == '0' else 'THAT'
        return f'@{pointer}\nM=D\n'
    if seg == 'static':
        return f'@Foo.{i}\nM=D\n'

def get_pop_asm(seg, i, p):
    if seg in ['pointer', 'static']:
        return f'{pop_stack()}{push_to_mem_asm(seg, i)}'
    if seg == 'temp':
        return f'@5\nD=A\n@{i}\nD=D+A\n@SP\nA=M\nM=D\n{pop_stack()}@SP\nA=M+1\nA=M\nM=D\n'
    return f'@{p[seg]}\nD=M\n@{i}\nD=D+A\n@SP\nA=M\nM=D\n{pop_stack()}@SP\nA=M+1\nA=M\nM=D\n'
