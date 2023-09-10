from .base import Scannable, DEBUG_LEVEL, OUTPUT_FORMAT
import os, json
class SSHAuth(Scannable):
   def __init__(self):
      Scannable.__init__(self, "SSHAuth", "SSH Authentication")
      self._log_paths = ["/var/log/auth.log"]

   def scan(self):
      Scannable.scan(self)

   def scanFile(self, logfile):
      if not os.path.exists(logfile):
         return
      if self._debug_level == DEBUG_LEVEL.INFO:
         print("Scanning SSHAuth log file: " + logfile)
      threats = {
         'failed': [],
         'logged_as_root': []
      }
      with open(logfile, "r") as f:
         for line in f:
            parts = line.split(" ")
            date = parts[0] + " " + parts[1] + " " + parts[2]
            ip = parts[3]
            message = parts[4:]
            if "failed" in message:
               threats["failed"].append({
                  "date": date,
                  "ip": ip,
                  "message": message
               })
            elif "session opened for user root" in message:
               threats["logged_as_root"].append({
                  "date": date,
                  "ip": ip,
                  "message": message
               })
      self.__threats = threats
      if len(threats) > 0 and self._debug_level == DEBUG_LEVEL.INFO:
         print("Found " + str(len(threats)) + " threats in SSHAuth log file: " + logfile)        
         for type_of_threat in threats:
            print("Found " + str(len(threats[type_of_threat])) + " " + type_of_threat + " threats in SSHAuth log file: " + logfile)

   def export(self):
      if self._output_format == OUTPUT_FORMAT.JSON:
         return json.dumps(self.__threats)
      elif self._output_format == OUTPUT_FORMAT.TEXT:
         res = ""
         for type_of_threat in self.__threats:
            res += type_of_threat + "\n"
            for threat in self.__threats[type_of_threat]:
               res += "\t" + str(threat) + "\n"
         return res