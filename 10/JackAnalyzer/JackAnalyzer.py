import sys
from pathlib import Path

from JackTokenizer import JackTokenizer

from Lib import check_args, get_files_list, clean_line


if __name__ == "__main__":
    try:
        check_args(sys.argv)

        files: list[Path] = get_files_list(sys.argv[1])
        for file in files:
            tokenizer: JackTokenizer = JackTokenizer(file)
            print("Advance 1")
            tokenizer.advance()
            print("Advance 2")
            tokenizer.advance()
            print("Advance 3")
            tokenizer.advance()
            tokenizer.close()

    # Error Catching
    except FileNotFoundError:
        print("File not found or cannot be opened")

    except IOError:
        print("An I/O error occurred while reading the file")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
