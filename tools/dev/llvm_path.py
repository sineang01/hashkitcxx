import sys
import os
head, tail = os.path.split(sys.argv[1])
head, tail = os.path.split(head)
sys.stdout.write(head)
