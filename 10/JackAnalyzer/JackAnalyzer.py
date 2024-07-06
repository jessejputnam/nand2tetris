import sys
from Analyzer import Analyzer


def check_args(args: list[str]):
    if len(args) == 1:
        raise Exception("No file specified")
    if len(args) > 2:
        raise Exception("Too many command line args")


if __name__ == "__main__":
    try:
        check_args(sys.argv)

        analyzer = Analyzer(sys.argv[1])
        analyzer.test_files()

    # Error Catching
    except FileNotFoundError:
        print("File not found or cannot be opened.")

    except IOError:
        print("An I/O error occurred while reading the file.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
