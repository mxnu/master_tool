from .base import Scannable, DEBUG_LEVEL, OUTPUT_FORMAT
import os, json
class Syslog(Scannable):
   def __init__(self):
      Scannable.__init__(self, "Syslog", "Syslog")
      self._log_paths = ["/var/log/apache2/access.log"]

   def scan(self):
      Scannable.scan(self)

   def scanFile(self, logfile):
      if not os.path.exists(logfile):
         return
      if self._debug_level == DEBUG_LEVEL.INFO:
         print("Scanning Syslog log file: " + logfile)
      threats = {
         'error': [],
         'warning': [],
         'denied': [],
         'high CPU': [],
      }
      with open(logfile, "r") as f:
         for line in f:
            parts = line.split(" ")
            date = parts[0] + " " + parts[1] + " " + parts[2]
            user = parts[3]
            message = parts[4:]
            if "error" in message:
               threats["error"].append({
                  "date": date,
                  "user": user,
                  "message": message
               })
            elif "warning" in message:
               threats["warning"].append({
                  "date": date,
                  "user": user,
                  "message": message
               })
            elif "denied" in message:
               threats["denied"].append({
                  "date": date,
                  "user": user,
                  "message": message
               })
            elif "high CPU" in message:
               threats["high CPU"].append({
                  "date": date,
                  "user": user,
                  "message": message
               })
      self.__threats = threats
      if len(threats) > 0 and self._debug_level == DEBUG_LEVEL.INFO:
         print("Found " + str(len(threats)) + " threats in Syslog log file: " + logfile)        
         for type_of_threat in threats:
            print("Found " + str(len(threats[type_of_threat])) + " " + type_of_threat + " threats in Syslog log file: " + logfile)


   def export(self):
      if self._output_format == OUTPUT_FORMAT.JSON:
         return json.dumps(self.__threats, indent=4)
      elif self._output_format == OUTPUT_FORMAT.TEXT:
         res = ""
         for type_of_threat in self.__threats:
            res += type_of_threat + "\n"
            for threat in self.__threats[type_of_threat]:
               res += "\t" + str(threat) + "\n"
         return res