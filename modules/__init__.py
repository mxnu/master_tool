from .base import *
from .apache import *
from .syslog import *
from .ssh_auth import *

def getAllScannables():
   return [c() for c in Scannable.__subclasses__()]