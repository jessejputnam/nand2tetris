// This file is part of www.nand2tetris.org
// and the book "The Elements of Computing Systems"
// by Nisan and Schocken, MIT Press.
// File name: projects/04/Fill.asm

// Runs an infinite loop that listens to the keyboard input.
// When a key is pressed (any key), the program blackens the screen
// by writing 'black' in every pixel;
// the screen should remain fully black as long as the key is pressed. 
// When no key is pressed, the program clears the screen by writing
// 'white' in every pixel;
// the screen should remain fully clear as long as no key is pressed.

//// Replace this comment with your code.
// KBD SCREEN

@SCREEN 
D=A 
@addr 
M=D
@8191
D=A
@max
M=D
@i 
M=0

(LOOP) 
    @i 
    D=M 
    @max 
    D=D-M 
    @RESTART 
    D;JGT

    // Key press check
    @KBD 
    D=M 
    @FILL 
    D;JGT 

    // White fill
    @SCREEN
    D=A
    @i 
    A=M+D
    M=0 
    @i 
    M=M+1
    @LOOP 
    0;JMP


// Black fill
(FILL)
    @SCREEN
    D=A
    @i 
    A=M+D
    M=-1 
    @i 
    M=M+1
    @LOOP 
    0;JMP

// Reset scanner to screen start
(RESTART)
    @i 
    M=0 
    @LOOP 
    0;JMP