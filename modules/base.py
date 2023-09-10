from abc import abstractmethod
from .enums import DEBUG_LEVEL, OUTPUT_FORMAT
import os

class Scannable:
   _log_paths = None
   _debug_level = DEBUG_LEVEL.NONE
   _output_format = OUTPUT_FORMAT.TEXT
   def __init__(self, name, description):
      self.name = name
      self.description = description

   # Check if apache is installed
   def canRun(self):
      if self._log_paths is None:
         return False
      self._log_paths = [path for path in self._log_paths if os.path.exists(path)]
      return len(self._log_paths) > 0

   # Scan log files
   def scan(self):
      if self._debug_level == DEBUG_LEVEL.INFO:
         print(f"Scanning {self.name}...")
      for path in self._log_paths:
         self.scanFile(path)

   # Scan log file
   @abstractmethod
   def scanFile(self, logfile):
      pass

   # Export results
   @abstractmethod
   def export(self):
      pass