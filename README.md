# ICF
Intel Conversion Framework

AUTHOR: Adam Burt

E-MAIL: BURT(dot)ADAM(at)GMAIL(dot)COM

DESCRIPTION:
This simple framework will convert source data to a useable destination data format. The framework monitors (multiple)
folders and will pass each file it finds to a set of "modules" that then process the data.

WHY:
When using multiple sources of intel, I have found they come in various formats. When one wants to put these data
sources into a central repository (such as CIF), they require converting to a format that is recognised. This framework
aims to provide a simple darg 'n drop method for this process.

HOW:
There are 3 main processes that run:

MONITOR:
Will actively monitor the desired folder(s) for files and pass them to "START" for distributed module processing.

DELETOR:
Will actively monitor an inter-process queue between the module and itself, containing files that need to be deleted
after being processed by the module.

START:
The main process that is responsible for passing new files to the individual modules


MODULES:
These can be whatever you like them to be. The only require a few things:
              "run" function - The main process calls the "run" function of the module to start it
                  "run" function must accept several parameters:
                        fileName      - e.g. "file1.csv"
                        fileNamePath  - e.g. "C:\file1.csv"
                        outputBase    - absolute path to "./output"
                        deleteQueue   - Queue to push abs filenames to for deletion
                        
  E.G:
  
  def run(fileName, fileNamePath, outputBase, deleteQueue):
    (check that fileNamePath exists and is of a format that this module understands and will process)
    (process the fileNamePath in whatever way you need)
    (output the results to outputBase\<whateveryouwant)
    (push the fileNamePath to deleteQueue> if you have processed it and want to remove it)
  
  
