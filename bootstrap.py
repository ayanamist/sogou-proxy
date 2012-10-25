import os
import sys

sys.dont_write_bytecode = True

executable_path = getattr(sys, 'executable', sys.argv[0])
executable_dir = os.path.dirname(executable_path)
sys.path.append(executable_dir)
for filename in os.listdir(executable_dir):
    if os.path.splitext(filename)[1].lower() == ".egg":
        sys.path.append(os.path.join(executable_dir, filename))

__file__ = os.path.abspath(os.path.splitext(executable_path)[0] +'.py')
if os.path.exists(__file__):
    execfile(__file__)
