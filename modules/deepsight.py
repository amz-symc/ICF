import os
import sys
import csv
import time

def checkFile(fileName):
    if ((fileName.split('.'))[1] == "csv"):
        f = open(fileName)
        reader = csv.reader(f)
        try:
            checkrow = reader.next()
        except:
            returned = "Not recognised"
            f.close()
            return returned
        try:
            second = checkrow[1]
        except:
            filetype = "Single"
            if len(checkrow[0]) > 15:
                contenttype = "hash"
                f.close()
                return ("{0} {1}".format(filetype,contenttype))
            else:
                contenttype = "IP"
                f.close()
                return ("{0} {1}".format(filetype,contenttype))
        if checkrow[0] == "ip":
            filetype = "IP"
            contenttype = "Standard"
        if checkrow[0] == "address":
            filetype = "IP"
            try:
                temp = checkrow[36]
            except:
                temp = "spam"
            if temp == "spam":
                contenttype = "spam"
            else:
                if checkrow[36] == "bot_name":
                    contenttype = "bot"
                if checkrow[36] == "attack_name":
                    contenttype = "attack"
                if checkrow[36] == "cnc_name":
                    contenttype = "cnc"
                if checkrow[36] == "malware_name":
                    contenttype = "malware"
                if checkrow[36] == "registration_person":
                    contenttype = "phishing / fraud"
        if checkrow[0] == "domain":
            filetype = "URL"
            contenttype = "Standard"
        if checkrow[0] == "domain_name":
            filetype = "URL"
            try:
                if checkrow[49] == "attack_name":
                    contenttype = "attack"
                if checkrow[49] == "cnc_name":
                    contenttype = "cnc"
                if checkrow[49] == "url":
                    contenttype = "phishing / fraud"
                if checkrow[49] == "malware_name":
                    contenttype = "malware"
            except:
                contenttype = "Standard"
        return ("{0} {1}".format(filetype,contenttype))
    else:
        returned = "Not recognised"
        return returned
    
def Converttb(f, g, filetype, contenttype):
    reader = csv.reader(f)
    writer = csv.writer(g, delimiter=',')
    reader.next()
    if contenttype == "hash":
        writer.writerow(("malware_hash", "description", "assessment", "confidence", "severity"))
    else:
        writer.writerow(("address", "description", "assessment", "confidence", "severity"))
    for row in reader:
        if filetype == "IP":
            if contenttype == "Standard":                
                writer.writerow((row[0], ("DeepsightIP - " + str(row[4])), row[4], (int(row[6]) * 10), "high"))
            if contenttype == "bot":                
                writer.writerow((row[0], row[36], row[36], (int(row[4]) * 10), "high"))
            if contenttype == "attack":                
                writer.writerow((row[0], row[37], row[36], int(row[4]), "high"))
            if contenttype == "cnc":                
                writer.writerow((row[0], row[49], row[36], (int(row[4]) * 10), "high"))
            if contenttype == "malware":                
                writer.writerow((row[0], row[37], row[36], (int(row[4]) * 10), "high"))
            if contenttype == "phishing / fraud":                
                writer.writerow((row[0], "Phishing / fraud", row[48], (int(row[4]) * 10), "high"))
            if contenttype == "spam":                
                writer.writerow((row[0], "Spam", row[14], (int(row[4]) * 10), "high"))
        if filetype == "URL":
            if contenttype == "Standard":                
                try:
                    writer.writerow((row[0], row[4], row[8], (int(row[6]) * 10), "high"))
                except:
                    pass
            if contenttype == "attack":
                try:
                    writer.writerow((row[0], row[49], row[51], (int(row[2]) * 10), "high"))
                except:
                    pass
            if contenttype == "cnc":
                try:
                    writer.writerow((row[0], row[49], row[51], (int(row[2]) * 10), "high"))
                except:
                    pass
            if contenttype == "malware":
                try:
                    writer.writerow((row[0], row[49], row[52], (int(row[2]) * 10), "high"))
                except:
                    pass
            if contenttype == "phishing / fraud":
                try:
                    writer.writerow((row[0], "Phishing / fraud", row[49], (int(row[2]) * 10), "high"))
                except:
                    pass
        if filetype == "Single":
            writer.writerow((row[0], "Imported", "Malicious", "70", "high"))


def Convertps(f, g, filetype, contenttype):
    reader = csv.reader(f)
    reader.next()
    writer = csv.writer(g, delimiter=',')
    writer.writerow(("ioctype", "value", "category", "reference", "severity", "tags"))
    for row in reader:        
        if filetype == "IP":
            writer.writerow(("ip", row[0], row[4], "Unknown", row[3], "Deepsight"))
        if filetype == "Advanced":
            if contenttype == "bot":
                writer.writerow(("ip", row[0], row[36], row[15], (int(row[4]) * 2), "Deepsight - Botnet"))
            if contenttype == "attack":
                writer.writerow(("ip", row[0], row[37], row[36], (int(row[4]) * 2),"Deepsight - Attack"))
            if contenttype == "cnc":
                writer.writerow(("ip", row[0], row[36], row[38], (int(row[4]) * 2), "Deepsight - CNC"))
            if contenttype == "malware":
                writer.writerow(("ip", row[0], row[37], row[36], (int(row[4]) * 2), "Deepsight - Malware"))
            if contenttype == "phishing / fraud":
                writer.writerow(("ip", row[0], "Phishing / fraud", row[48], (int(row[4]) * 2), "Deepsight - Phishing / fraud"))
            if contenttype == "spam":
                writer.writerow(("ip", row[0], "Spam", row[14], (int(row[4]) * 2), "Deepsight - Spam"))


def ConvertKFF(f, g, filetype, contenttype):
    reader = csv.reader(f)
    reader.next()
    writer = csv.writer(g, delimiter=',',quoting=csv.QUOTE_ALL)
    writer.writerow(("MD5", "SHA1", "FileNames"))
    for row in reader:        
        writer.writerow((row[0], "", ""))
        duplicatePrevious = row[0]


def ConvertSO(f, g, filetype, contenttype):
    reader = csv.reader(f)
    reader.next()
    writer = csv.writer(g, delimiter=',')
    for row in reader:
        if filetype == "IP":
            if contenttype == "Standard":
                writer.writerow((row[0], ("DeepsightIP - " + str(row[4])), "malicious", (int(row[6]) * 10), "high", "Deepsight IP-Std"))
            if contenttype == "bot":
                writer.writerow((row[0], row[36], "botnet", (int(row[4]) * 10), "high", "Deepsight IP-Botnet"))
            if contenttype == "attack":
                writer.writerow((row[0], row[36], "malicious", int(row[4]), "high", "Deepsight IP-Attack"))
            if contenttype == "cnc":
                writer.writerow((row[0], row[36], "botnet", (int(row[4]) * 10), "high", "Deepsight IP-CnC"))
            if contenttype == "malware":
                writer.writerow((row[0], row[36], "malware", (int(row[4]) * 10), "high", "Deepsight IP-Malware"))
            if contenttype == "phishing / fraud":
                writer.writerow((row[0], "Phishing / fraud", "malicious", (int(row[4]) * 10), "high", "Deepsight IP-Phishing / fraud"))
            if contenttype == "spam":
                writer.writerow((row[0], "Spam", "malicious", (int(row[4]) * 10), "high", "Deepsight IP-Spam"))
        if filetype == "URL":
            if contenttype == "Standard":
                writer.writerow((row[0], row[4], "malicious", (int(row[6]) * 10), "high", "Deepsight URL-Std"))
            if contenttype == "attack":
                try:
                    writer.writerow((row[0], row[49], "malicious", (int(row[2]) * 10), "high", "Deepsight URL-Attack"))
                except:
                    pass
            if contenttype == "cnc":
                try:
                    writer.writerow((row[0], row[49], "botnet", (int(row[2]) * 10), "high", "Deepsight URL-CnC"))
                except:
                    pass
            if contenttype == "malware":
                try:
                    writer.writerow((row[0], row[49], "malware", (int(row[2]) * 10), "high", "Deepsight URL-Malware"))
                except:
                    pass
            if contenttype == "phishing / fraud":                
                writer.writerow((row[0], "Phishing / fraud", "malicious", (int(row[2]) * 10), "high", "Deepsight URL-Phising / fraud"))
        if ((filetype == "Single") and (contenttype == "IP")):
            writer.writerow((row[0], "Imported", "malicious", "70", "high", "Single list import"))


def run(fileName, fileNamePath, outputBase, deleteQueue):
    canRemove = 0
    if os.path.exists(fileNamePath):
        validFile = checkFile(fileNamePath)
        temp = validFile.split(" ")
        if (validFile != "Not recognised"):
            if ((validFile.find("IP") != -1) or (validFile.find("URL") != -1)):
                outputFile = os.path.join(outputBase, "TB")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                Converttb(f, g, temp[0], temp[1])
                canRemove = 1
                f.close()
                g.close()
                outputFile = os.path.join(outputBase, "SO")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                ConvertSO(f, g, temp[0], temp[1])
                f.close()
                g.close()
                canRemove = 1
            if ((validFile.find("IP") != -1) and (validFile.find("Single")== -1) and (os.path.exists(fileNamePath))):
                outputFile = os.path.join(outputBase, "PS")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                Convertps(f, g, temp[0], temp[1])
                f.close()
                g.close()
                canRemove = 1
            if ((validFile.find("hash") != -1) and (os.path.exists(fileNamePath))):
                outputFile = os.path.join(outputBase, "KFF")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                ConvertKFF(f, g, temp[0], temp[1])
                f.close()
                g.close()
                canRemove = 1
                outputFile = os.path.join(outputBase, "TB")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                Converttb(f, g, temp[0], temp[1])
                f.close()
                g.close()
                canRemove = 1
            if ((validFile.find("Single IP") != -1) and (os.path.exists(fileNamePath))):
                outputFile = os.path.join(outputBase, "PS")
                outputFile = os.path.join(outputFile, fileName)
                f = open(fileNamePath, "rb")
                g = open(outputFile, "wb")
                Convertps(f, g, temp[0], temp[1])
                f.close()
                g.close()
                canRemove = 1
        if (canRemove == 1):
            deleteQueue.put(fileNamePath)


def main():
    print "This module cannot be run standalone"

if __name__ == '__main__':
    main()

