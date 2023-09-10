from .base import Scannable, DEBUG_LEVEL, OUTPUT_FORMAT
import os, json
class Apache(Scannable):
   def __init__(self):
      Scannable.__init__(self, "Apache", "Apache web server")
      self._log_paths = ["/var/log/apache2/access.log"]
      self.__threats = None

   def canRun(self):
      return Scannable.canRun(self)

   def scan(self):
      Scannable.scan(self)

   def scanFile(self, logfile):
      if not os.path.exists(logfile):
         return
      if self._debug_level == DEBUG_LEVEL.INFO:
         print("Scanning Apache log file: " + logfile)
      threats = {
         'fatal_error': [],
         'not_found': [],
         'unauthorized': [],
      }
      with open(logfile, "r") as f:
         for line in f:
            parts = line.split(" ")
            ip = parts[0]
            date = parts[3]
            method = parts[5]
            path = parts[6]
            status = parts[8]
            if status.startswith("5"):
               threats["fatal_error"].append({
                  "ip": ip,
                  "date": date,
                  "method": method,
                  "path": path,
                  "status": status
               })
            elif status == "404":
               threats["not_found"].append({
                  "ip": ip,
                  "date": date,
                  "method": method,
                  "path": path,
                  "status": status
               })
            elif status.startswith("4"):
               threats["unauthorized"].append({
                  "ip": ip,
                  "date": date,
                  "method": method,
                  "path": path,
                  "status": status
               })
      self.__threats = threats
      if len(threats) > 0 and self._debug_level == DEBUG_LEVEL.INFO:
         print("Found " + str(len(threats)) + " threats in Apache log file: " + logfile)        
         for type_of_threat in threats:
            print("Type of threat: " + type_of_threat)
            if len(threats[type_of_threat]) == 0:
               print("* No threats found")
            for threat in threats[type_of_threat]:
               print("IP: " + threat["ip"])
               print("Date: " + threat["date"])
               print("Method: " + threat["method"])
               print("Path: " + threat["path"])
               print("Status: " + threat["status"])
               print()
   
   def export(self):
      if self._output_format == OUTPUT_FORMAT.JSON:
         return json.dumps(self.__threats)
      return self.__threats