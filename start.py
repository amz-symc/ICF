import sys
import os
from multiprocessing import Process, Queue, Lock
import time
import signal


def signal_handler(signal, frame):
    print "\n\nAttempting to kill sub-processes"
    sys.exit(0)

def loadConfig(item,configFile):
    #This module finds 'item' in the 'configFile' and returns it's = operand
    f = open(configFile)
    if (item == "MONITORPATH"):
        value = []
    else:
        value = ""
    for line in f:
        if (line[0] != '#'):
            items = line.split('=')
            if (items[0] == item):
                current = (items[1]).strip('\n')
                current = current.strip('\r')
                current = current.replace("\"","")
                if (item == "MONITORPATH"):
                    value.append(current)
                else:
                    value = current
    f.close()
    return value
    


def main():
    #Paths---------------------------------------------------------------
    sys.path.append(os.path.abspath('.'))
    sys.path.append(os.path.abspath('./modules'))
    configFile = os.path.abspath('./config/config.txt')
    modulesPath = os.path.abspath('./modules')
    try:
        f = open(configFile)
        f.close()
    except:
        print "Unable to open {0}".format(configFile)
        sys.exit()


    #Variables------------------------------------------------------------
    monitorPath = loadConfig("MONITORPATH",configFile)
    for x in monitorPath:        
        if (os.path.exists(x) == False):
            print "Monitor path \"{0}\" does not exist".format(x)
            quit()
    autoexit = int(loadConfig("AUTOEXIT",configFile))
    baseOutput = os.path.abspath(loadConfig("BASEOUTPUT",configFile))
    try:
        os.mkdir(baseOutput)
    except:
        pass
    monitorInterval = int(loadConfig("MONITORINTERVAL",configFile))
    print """

==================================================

=============\\
CONFIG LOADED |>
=============/

Monitor Path = {0}
Monitor interval = {2}(seconds)
Automatically exit = {1}(seconds)
Base output folder = {3}

==================================================



""".format(monitorPath,autoexit,monitorInterval,baseOutput)


    #Gather modules in modules folder--------------------------------------
    modules = []
    for item in os.listdir(modulesPath):
        if os.path.isfile((os.path.join(modulesPath,item))):
            itemSplit = item.split('.')
            if (itemSplit[1] == "py"):
                modules.append(itemSplit[0])
    modulesImport = map(__import__,modules)
    modulesImport
    print ("\n")



    #Imports-----------------------------------------------------------------
    import monitor
    import deletor
    print ("\n")


    #Establish queues and locks--------------------------------------------------------
    deleteQueue = Queue()
    fileQueue = Queue()
    terminateQueue = Queue()
    locker = Lock()


    #Start monitoring the monitor folder---------------------------------------
    myPID = os.getpid()
    for x in monitorPath:        
        mon = Process(target=monitor.run, args=(x,fileQueue,locker,terminateQueue,monitorInterval, myPID))
        mon.start()
    dele = Process(target=deletor.run, args=(deleteQueue,locker,terminateQueue,myPID))
    dele.start()
    startTime = time.clock()
    timer = 0
    signal.signal(signal.SIGINT, signal_handler)

    #Start processing the file queue
    while True:
        if (fileQueue.empty() == False):
            currentFile = fileQueue.get()
            for x in range(len(modules)):
                if os.path.exists(currentFile[1]):
                    p = Process(target=modulesImport[x].run, args=(currentFile[0], currentFile[1], baseOutput,deleteQueue))
                    p.start()
                    #modulesImport[x].run(currentFile[0], currentFile[1], baseOutput,deleteQueue)
        if (autoexit > 0):
            timer = time.clock() - startTime
            if (timer > autoexit):
                break
        time.sleep(0.5)
    print "Sending TERMSIG"
    terminateQueue.put('exit')
    time.sleep(monitorInterval)
    mon.terminate()
    dele.terminate()


if __name__ == '__main__':
    main()
