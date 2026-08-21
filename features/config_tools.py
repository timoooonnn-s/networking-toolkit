"""
features/config_tools.py
-------------------------
Configuration & Automation Tools
==================================
Refactored from the original monolith's Category D (Configuration &
Automation) minus SSH bulk runner (→ features/ssh_runner.py) and
rollback generator (→ features/rollback.py).

Tools
-----
    tool_config_diff()    — Unified diff of two config files
    tool_snippet_lib()    — JSON-backed configuration snippet library
    tool_diagram_gen()    — ASCII network topology diagram
    tool_jinja_render()   — Jinja2 template renderer with JSON data files
    tool_intf_parser()    — Cisco-style interface config extractor
"""

from __future__ import annotations

import difflib
import json
import os

from core.colors import C_BOLD, C_CYAN, C_GREEN, C_RED, C_RESET, C_YELLOW
from core.dependency_check import check_dependency
from core.paths import SNIPPET_FILE

# ---------------------------------------------------------------------------
# Config File Diff
# ---------------------------------------------------------------------------

def tool_config_diff() -> None:
    """Compare two configuration files with a coloured unified diff."""
    print(f"{C_BOLD}--- Configuration File Diff ---{C_RESET}")

    f1_path = input("File 1 (old / candidate): ").strip()
    f2_path = input("File 2 (new / running):   ").strip()

    if not os.path.exists(f1_path) or not os.path.exists(f2_path):
        print(f"{C_RED}One or both files not found.{C_RESET}")
        return

    try:
        with open(f1_path) as f1, open(f2_path) as f2:
            f1_lines = f1.readlines()
            f2_lines = f2.readlines()

        diff       = difflib.unified_diff(f1_lines, f2_lines, fromfile="OLD", tofile="NEW", lineterm="")
        found_diff = False

        print(f"\n{C_BOLD}--- Diff Output ---{C_RESET}")
        for line in diff:
            found_diff = True
            if line.startswith("+") and not line.startswith("+++"):
                print(f"{C_GREEN}{line}{C_RESET}")
            elif line.startswith("-") and not line.startswith("---"):
                print(f"{C_RED}{line}{C_RESET}")
            elif line.startswith("@"):
                print(f"{C_CYAN}{line}{C_RESET}")
            else:
                print(line)

        if not found_diff:
            print(f"{C_GREEN}Files are identical.{C_RESET}")

    except Exception as exc:
        print(f"{C_RED}Error processing diff: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Configuration Snippet Library
# ---------------------------------------------------------------------------

def _load_snippets() -> dict:
    """Load snippets from the JSON store, returning an empty dict on error."""
    if os.path.exists(SNIPPET_FILE):
        try:
            with open(SNIPPET_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"{C_YELLOW}Warning: Could not parse {SNIPPET_FILE} — starting fresh.{C_RESET}")
    return {}


def _save_snippets(snippets: dict) -> None:
    with open(SNIPPET_FILE, "w") as f:
        json.dump(snippets, f, indent=4)


def tool_snippet_lib() -> None:
    """Manage a JSON-backed library of reusable configuration snippets."""
    print(f"{C_BOLD}--- Configuration Snippet Library ---{C_RESET}")
    snippets = _load_snippets()
    print(f"Stored snippets: {len(snippets)}")
    print("  1. List / view snippet")
    print("  2. Add snippet")
    print("  3. Delete snippet")
    choice = input("Choice: ").strip()

    if choice == "1":
        if not snippets:
            print(f"{C_YELLOW}No snippets stored yet.{C_RESET}")
            return
        print(f"\n{C_BOLD}Available Snippets:{C_RESET}")
        for name in sorted(snippets):
            print(f"  - {name}")
        view_name = input("\nEnter name to view (blank to cancel): ").strip()
        if view_name in snippets:
            print(f"\n{C_GREEN}--- {view_name} ---{C_RESET}")
            print(snippets[view_name])
            print(f"{C_GREEN}{'─' * 40}{C_RESET}")
        elif view_name:
            print(f"{C_RED}Snippet '{view_name}' not found.{C_RESET}")

    elif choice == "2":
        name = input("Snippet name (e.g. 'cisco_ntp_config'): ").strip()
        if not name:
            print(f"{C_RED}Name cannot be empty.{C_RESET}")
            return
        print("Enter content (finish with a line containing only 'EOF'):")
        lines: list[str] = []
        while True:
            line = input()
            if line.strip() == "EOF":
                break
            lines.append(line)
        snippets[name] = "\n".join(lines)
        _save_snippets(snippets)
        print(f"{C_GREEN}Snippet '{name}' saved.{C_RESET}")

    elif choice == "3":
        name = input("Snippet name to delete: ").strip()
        if name in snippets:
            del snippets[name]
            _save_snippets(snippets)
            print(f"{C_GREEN}Snippet '{name}' deleted.{C_RESET}")
        else:
            print(f"{C_RED}Snippet '{name}' not found.{C_RESET}")
    else:
        print(f"{C_RED}Invalid option.{C_RESET}")


# ---------------------------------------------------------------------------
# ASCII Network Diagram Generator
# ---------------------------------------------------------------------------

def tool_diagram_gen() -> None:
    """Generate a simple ASCII tree topology from connection pairs."""
    print(f"{C_BOLD}--- ASCII Network Diagram Generator ---{C_RESET}")
    print("Enter connections as:  Source -> Destination")
    print("Type 'DRAW' to render.\n")

    connections: list[tuple[str, str]] = []
    while True:
        line = input("> ").strip()
        if line.upper() == "DRAW":
            break
        if "->" in line:
            parts = line.split("->", 1)
            connections.append((parts[0].strip(), parts[1].strip()))

    if not connections:
        return

    # Build adjacency map
    adj: dict[str, list[str]] = {}
    dests: set[str] = set()
    for src, dst in connections:
        adj.setdefault(src, []).append(dst)
        dests.add(dst)

    all_nodes = set(adj.keys()) | dests
    # A topology where every node is also a destination is a pure cycle and
    # has no root; start from the first connection's source so the output is
    # deterministic rather than dependent on set ordering.
    roots     = sorted(n for n in all_nodes if n not in dests) or [connections[0][0]]

    def _print_tree(
        node: str,
        prefix: str = "",
        is_last: bool = True,
        seen: frozenset[str] = frozenset(),
    ) -> None:
        """
        Render one subtree.

        *seen* carries the nodes on the path from the root to here, so a
        cyclic topology ('A -> B' plus 'B -> A', which is how anyone would
        describe a redundant link) prints the loop once and stops.  Without
        it the recursion ran until RecursionError, after dumping megabytes to
        the terminal and taking the whole session down with it.
        """
        connector = "└── " if is_last else "├── "
        if node in seen:
            print(f"{prefix}{connector}[ {C_YELLOW}{node}{C_RESET} ]  "
                  f"{C_YELLOW}← loop, already shown{C_RESET}")
            return

        print(f"{prefix}{connector}[ {C_CYAN}{node}{C_RESET} ]")
        children = adj.get(node, [])
        for i, child in enumerate(children):
            new_prefix = prefix + ("    " if is_last else "│   ")
            _print_tree(child, new_prefix, i == len(children) - 1, seen | {node})

    print(f"\n{C_BOLD}--- Topology ---{C_RESET}")
    for root in roots:
        _print_tree(root)


# ---------------------------------------------------------------------------
# Jinja2 Template Renderer
# ---------------------------------------------------------------------------

def tool_jinja_render() -> None:
    """Render a Jinja2 .j2 template using a JSON data file."""
    print(f"{C_BOLD}--- Jinja2 Template Renderer ---{C_RESET}")

    if not check_dependency("jinja2"):
        return

    from jinja2 import Environment, FileSystemLoader  # lazy import

    template_path = input("Path to .j2 template: ").strip()
    data_path     = input("Path to .json data:    ").strip()

    if not os.path.exists(template_path) or not os.path.exists(data_path):
        print(f"{C_RED}One or both files not found.{C_RESET}")
        return

    try:
        with open(data_path) as f:
            data = json.load(f)

        env_dir, tmpl_file = os.path.split(os.path.abspath(template_path))
        env      = Environment(loader=FileSystemLoader(env_dir))
        template = env.get_template(tmpl_file)
        rendered = template.render(data)

        print(f"\n{C_BOLD}--- Rendered Output ---{C_RESET}")
        print(f"{C_CYAN}{rendered}{C_RESET}")

        if input("\nSave to file? (y/N): ").strip().lower() == "y":
            out_path = input("Output filename: ").strip()
            with open(out_path, "w") as f:
                f.write(rendered)
            print(f"{C_GREEN}Saved to {out_path}{C_RESET}")

    except Exception as exc:
        print(f"{C_RED}Rendering failed: {exc}{C_RESET}")


# ---------------------------------------------------------------------------
# Interface Config Parser
# ---------------------------------------------------------------------------

def tool_intf_parser() -> None:
    """
    Extract interface name, IP address, and description from a
    Cisco-style configuration file.
    """
    print(f"{C_BOLD}--- Interface Config Parser ---{C_RESET}")
    path = input("Path to config file: ").strip()

    if not os.path.exists(path):
        print(f"{C_RED}File not found.{C_RESET}")
        return

    interfaces: list[dict] = []
    current: dict | None   = None

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()

                if line.startswith("interface "):
                    if current:
                        interfaces.append(current)
                    current = {"name": line.split()[1], "ip": "N/A", "desc": "N/A"}

                elif current and line.startswith("description "):
                    current["desc"] = " ".join(line.split()[1:])

                elif current and line.startswith("ip address "):
                    parts = line.split()
                    if len(parts) >= 3:
                        current["ip"] = parts[2]

        if current:
            interfaces.append(current)

        if not interfaces:
            print(f"{C_YELLOW}No interface blocks found in the file.{C_RESET}")
            return

        print(f"\n{C_BOLD}{'Interface':<22} {'IP Address':<18} {'Description'}{C_RESET}")
        print("─" * 70)
        for intf in interfaces:
            print(f"{intf['name']:<22} {C_GREEN}{intf['ip']:<18}{C_RESET} {intf['desc']}")

    except Exception as exc:
        print(f"{C_RED}Error parsing file: {exc}{C_RESET}")
