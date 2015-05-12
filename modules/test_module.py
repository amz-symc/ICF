import os
import sys
import csv
import re

#This module simply converts a single list of IP addresses from CSV to text format



#Each module should have a pre-check to see if it is iteself, responsible for processing the file
def checkFile(fileName):
    returned = "Not recognised"
    if ((fileName.split('.'))[1] == "csv"):
        f = open(fileName)
        reader = csv.reader(f)
        try:
            for line in reader:
                secondColumn = reader[1]
            returned = "Not recognised"
        except:
            row = reader.next()
            if ((re.match("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}",row[0]))):
                returned = "valid"
        f.close()
        return returned




#The "run" procedure is what is called by the main "start" process when a file is found in the monitored folder(s)
#It is passed several attributes:

#   fileName = the file name only ("file.csv")
#   fileNamePath is the full path and file ("C:\file.csv")
#   outputBase is the FULL path of "./output" directory - append as necessary
#   deleteQueue is a Queue of files that get deleted by the deletor process - we push our processed filename to this for deletion after conversion

def run(fileName, fileNamePath, outputBase, deleteQueue):
    if os.path.exists(fileNamePath):
        validFile = checkFile(fileNamePath)
        if (validFile == "valid"):
            f = open(fileNamePath, "rb")
            myFile = "C:\\myfile.txt"
            g = open(myFile, "wb")
            for line in reader:
                g.writelines(line[0])
            g.close()
            f.close()
            deleteQueue.put(fileNamePath) #This command will pass the full file name to the delteor process queue to be removed

def main():
    print "This module cannot be run standalone"

if __name__ == '__main__':
    main()

