"""Assert an echoed request carried header == value. Usage: <file> <header> <value>"""
import json, sys

h = json.load(open(sys.argv[1]))["headers"]
sys.exit(0 if h.get(sys.argv[2].lower()) == sys.argv[3] else 1)
