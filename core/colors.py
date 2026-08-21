"""
core/colors.py
--------------
Centralised ANSI color constants and terminal UI helpers shared across
every module in the SysNet Toolkit.  Import with:

    from core.colors import C_GREEN, C_RESET, print_header, wait_for_user
"""

import os
import sys

# ---------------------------------------------------------------------------
# ANSI escape codes
# ---------------------------------------------------------------------------
C_RESET   = "\033[0m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_BOLD    = "\033[1m"

VERSION = "2.2.0"


def print_header() -> None:
    """Clear the terminal and render the SysNet ASCII banner + version box."""
    os.system("cls" if os.name == "nt" else "clear")

    BOX_WIDTH = 66


    print(" _______             __                             __    .__                   ___________                .__    __    .__   __       ")
    print(" ╲      ╲    ____  _╱  │_ __  _  __  ____  _______ │  │ __│__│  ____     ____   ╲__    ___╱  ____    ____  │  │  │  │ __│__│_╱  │_     ")
    print(" ╱   │   ╲ _╱ __ ╲ ╲   __╲╲ ╲╱ ╲╱ ╱ ╱  _ ╲ ╲_  __ ╲│  │╱ ╱│  │ ╱    ╲   ╱ ___╲    │    │    ╱  _ ╲  ╱  _ ╲ │  │  │  │╱ ╱│  │╲   __╲    ")
    print("╱    │    ╲╲  ___╱  │  │   ╲     ╱ (  <_> ) │  │ ╲╱│    < │  ││   │  ╲ ╱ ╱_╱  >   │    │   (  <_> )(  <_> )│  │__│    < │  │ │  │      ")
    print("╲____│__  ╱ ╲___  > │__│    ╲╱╲_╱   ╲____╱  │__│   │__│_ ╲│__││___│  ╱ ╲___  ╱    │____│    ╲____╱  ╲____╱ │____╱│__│_ ╲│__│ │__│      ")
    print("        ╲╱      ╲╱                                      ╲╱         ╲╱ ╱_____╱                                         ╲╱               ")
    print("                                                                                                                                       ")
    print("                                                                                        by timmy        |       v2.1                   ")
    print("                                                                                                                                       ")
    print("                                                                                                                                       ")
    

def wait_for_user() -> None:
    """Pause execution until the operator presses Enter."""
    input(f"\n{C_YELLOW}Press Enter to return to main menu...{C_RESET}")
