import sys
import time
import os
import signal

def signal_handler(signal, frame):
    print "\n\nDELETOR: Stopping"
    sys.exit(1)

def main():
    print 'DELETOR: This module cannot be run directly'
    
def run(deleteQueue,locker,terminateQueue,PPID):
    print 'DELETOR: Listening on Delete Queue'
    signal.signal(signal.SIGINT, signal_handler)
    while True:
        
        #Check to see if there are any files in the queue to delete
        if(deleteQueue.empty() == False):
            for x in range(0, int(deleteQueue.qsize())):
                fileName = deleteQueue.get()
                if os.path.exists(fileName):
                    try:
                        os.remove(fileName)
                    except:
                        pass
                    
        #Always check the queue for an exit command
        if (terminateQueue.empty() == False):
            break
        try:
            os.kill(PPID,0)
        except OSError:
            break
        time.sleep(0.1)


if (__name__ == '__main__'):
    main()
    

