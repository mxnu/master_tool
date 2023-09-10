import modules
from modules.enums import DEBUG_LEVEL
from modules.enums import OUTPUT_FORMAT
import argparse, os

def main():
   parser = argparse.ArgumentParser(description="Scan for threats")
   parser.add_argument("-d", "--debug", help="Debug level", choices=[DEBUG_LEVEL.INFO.value, DEBUG_LEVEL.NONE.value], default=DEBUG_LEVEL.NONE.value)
   parser.add_argument("-f", "--format", help="Output format", choices=[OUTPUT_FORMAT.JSON.value, OUTPUT_FORMAT.TEXT.value], default=OUTPUT_FORMAT.TEXT.value)
   parser.add_argument("-o", "--output", help="Output file", required=True)
   parser.add_argument("-p", "--prefix", help="Prefix for json export")
   args = parser.parse_args()

   # Validate arguments
   if parser.format == OUTPUT_FORMAT.JSON.value:
      if parser.prefix is None:
         parser.error("JSON output requires a prefix")
      # Validate if output is directory
      if os.path.isdir(parser.output):
         parser.error("JSON output requires a file, not a directory")
   elif parser.format == OUTPUT_FORMAT.TEXT.value:
      if os.path.isdir(parser.output) and parser.prefix is None:
         parser.error("Text output requires a prefix if output is a directory")
      else:
         abspath = os.path.abspath(parser.output)
         dirname = os.path.dirname(abspath)
         if not os.path.exists(dirname):
            parser.error("Directory does not exist")
         if not os.path.isdir(dirname):
            parser.error("Output is not a directory")

   scannables = modules.getAllScannables()
   for scannable in scannables:
      scannable._debug_level = DEBUG_LEVEL(args.debug)
      scannable._output_format = OUTPUT_FORMAT(args.output)
      if scannable.canRun():
         scannable.scan()
         res = scannable.export()
         output_path = os.path.abspath(args.output)
         if args.format == OUTPUT_FORMAT.JSON.value:
            with open(f'{output_path}/{args.prefix}_{scannable.name}.json', "w") as f:
               f.write(res)
         elif args.format == OUTPUT_FORMAT.TEXT.value:
            if args.prefix is None:
               with open(output_path, "a") as f:
                  f.write(scannable.name + "\n")
                  f.write(res + "\n")

if __name__ == '__main__':
   main()