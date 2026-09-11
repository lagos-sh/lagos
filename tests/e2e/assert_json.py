"""Assert a JSON file has key == value. Usage: assert_json.py <file> <key> <value>"""
import json, sys

try:
    actual = json.load(open(sys.argv[1]))[sys.argv[2]]
except Exception:
    sys.exit(1)
sys.exit(0 if str(actual) == sys.argv[3] else 1)
