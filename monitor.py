import sys
import os
import time
import platform
from multiprocessing import Process, Queue, Lock
import signal

def signal_handler(signal, frame):
    print "\n\nMONITOR: Stopping"
    sys.exit(1)
    
def main():
    print 'MONITOR: This module cannot be run directly'

def run(monitorPath,fileQueue,locker,exitQueue,interval,PPID):
    signal.signal(signal.SIGINT, signal_handler)
    print "MONITOR: Monitoring {0}".format(monitorPath)
    while True:
        files = []
        #Get all files in the monitor folder
        #locker.acquire()
        if (len(os.listdir(monitorPath)) > 0):            
            for item in os.listdir(monitorPath):
                if (os.path.isfile((os.path.join(monitorPath,item))) == True):
                    files.append(item)

        #Push files to the queue for processing
        if (len(files) > 0):
            for fileName in files:
                temp = (fileName,(os.path.join(monitorPath,fileName)))
                temp2 = (fileName,(os.path.join(monitorPath,"tmp.tmp")))
                try:
                    os.rename(temp[1], temp2[1])
                    os.rename(temp2[1], temp[1])
                    fileQueue.put(temp)
                except:
                    pass
        #locker.release()
        #Always check the queue for an exit command
        if (exitQueue.empty() == False):
            break
        try:
            os.kill(PPID,0)
        except OSError:
            break
        time.sleep(interval)



if (__name__ == '__main__'):
    main()
    
