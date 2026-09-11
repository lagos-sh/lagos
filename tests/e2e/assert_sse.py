"""Assert an SSE capture arrived incrementally rather than in one buffered flush."""
import re, sys

stamps = [float(m) for m in re.findall(r"at (\d+\.\d+)", open(sys.argv[1]).read())]
# The fixture emits five events a second apart; buffering collapses the spread.
sys.exit(0 if len(stamps) == 5 and (stamps[-1] - stamps[0]) > 3 else 1)
