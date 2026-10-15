"""Internal bounded VBA parser process. Never executes a macro."""
import json
import sys

from .active import _vba_facts
from .config import DEFAULT_LIMITS


def main():
    data = sys.stdin.buffer.read(DEFAULT_LIMITS.max_attachment_bytes + 1)
    if len(data) > DEFAULT_LIMITS.max_attachment_bytes:
        raise ValueError('VBA input byte limit exceeded')
    observations, scripts, warnings = _vba_facts(data, sys.argv[1])
    sys.stdout.write(json.dumps({'observations':observations, 'scripts':scripts, 'warnings':warnings}))


if __name__ == '__main__':
    main()
