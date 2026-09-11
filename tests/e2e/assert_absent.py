"""Assert an echoed request did NOT carry a header. Usage: <file> <header>"""
import json, sys

h = json.load(open(sys.argv[1]))["headers"]
sys.exit(1 if sys.argv[2].lower() in h else 0)
