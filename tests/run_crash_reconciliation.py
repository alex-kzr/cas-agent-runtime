"""Apply no-child/no-network guards before importing product modules or fixtures."""
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

test = Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).with_name('test_crash_reconciliation.py')
sys.argv=[str(test)]
with patch('subprocess.Popen',side_effect=AssertionError('NO_CHILD_PROCESS')),patch('os.system',side_effect=AssertionError('NO_SHELL')),patch('socket.socket',side_effect=AssertionError('NO_SOCKET')):
    runpy.run_path(str(test),run_name='__main__')
