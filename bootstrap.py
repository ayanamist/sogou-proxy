import os
import sys

sys.dont_write_bytecode = True

executable_path = getattr(sys, 'executable', sys.argv[0])

sys.path.append(os.path.dirname(executable_path))

__file__ = os.path.abspath(os.path.splitext(executable_path)[0] +'.py')
if os.path.exists(__file__):
    execfile(__file__)
