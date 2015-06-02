import sys,os
import csv
import time
import argparse
import xml.etree.ElementTree as ET
import re


class MATI(object):

    def __init__(self,srcfile):
        self.data = ET.parse(srcfile)


    def sanitise(self,info):
        i_dict = {}
        root = self.data.getroot() 
        metadata = root.find('metadata')
        indicators = metadata.find('extracted_indicators')
        for indicator in indicators:
            i_type = indicator.find('indicator_type')
            i_val  = indicator.find('indicator')

            if i_type.text not in i_dict:
                i_dict[i_type.text] = []
            
            i_dict[i_type.text].append(i_val.text.replace('[.]','.'))

        i_dict['info'] = info
        return i_dict
        


class KFF(object):

    def __init__(self,data):
        self.data = data
        self.headers = ['MD5']

    def convert(self,destfile):
        with open(destfile,'wb+') as f:
            writer = csv.writer(f, delimiter=',')
            writer.writerow(self.headers)

            if 'file_md5' in self.data:
                for md5 in self.data['file_md5']:
                    writer.writerow([md5])



class BRO(object):

    def __init__(self,data):
        self.data = data
        #fields indicator   indicator_type  meta.source meta.desc  meta.severity   meta.confidence
        self.headers = ''.join(['#fields indicator\t','indicator_type\t','meta.source\t','meta.desc\t','meta.severity\t','meta.confidence\n'])


    def convert(self,destfile):

        with open(destfile, 'wb+') as f:
            f.write(self.headers)
            if 'file_md5' in self.data:
                for md5 in self.data['file_md5']:
                    f.write(md5+'\t'+'Intel::FILE_HASH'+'\t'+'MATI'+'\t'+self.data['info']+'\t'+'high'+'\t'+'100'+'\n')

            if 'url' in self.data:
                for url in self.data['url']:
                    f.write(url+'\t'+'Intel::URL'+'\t'+'MATI'+'\t'+self.data['info']+'\t'+'high'+'\t'+'100'+'\n')   

            if 'domain' in self.data:
                for domain in self.data['domain']:
                    f.write(domain+'\t'+'Intel::DOMAIN'+'\t'+'MATI'+'\t'+self.data['info']+'\t'+'high'+'\t'+'100'+'\n')   

            if 'ip_address' in self.data:
                for ip in self.data['ip_address']:
                    f.write(ip+'\t'+'Intel::ADDR'+'\t'+'MATI'+'\t'+self.data['info']+'\t'+'high'+'\t'+'100'+'\n') 

            if 'email_from_address' in self.data:
                for email in self.data['email_from_address']:
                    f.write(email+'\t'+'Intel::EMAIL'+'\t'+'MATI'+'\t'+self.data['info']+'\t'+'high'+'\t'+'100'+'\n')                 




class ThreatBridge(object):

    def __init__(self,data):
        self.data = data
        self.headers_url = ["address", "description", "assessment", "confidence", "severity"]
        self.headers_hash = ["malware_hash", "description", "assessment", "confidence", "severity"]

    def convert(self,destfile):
        # ThreatBrdige will output two files
        # One for domains and one for md5s
        destfile_url = destfile+'_url.csv'
        destfile_hash = destfile+'_hash.csv'
        with open(destfile_hash,'wb+') as f:
            writer = csv.writer(f, delimiter=',')
            writer.writerow(self.headers_hash)

            if 'file_md5' in self.data:
                for md5 in self.data['file_md5']:
                    writer.writerow([md5,self.data['info'],'','100','high'])

        with open(destfile_url,'wb+') as f:
            writer = csv.writer(f, delimiter=',')
            writer.writerow(self.headers_url)

            if 'domain' in self.data:
                for domain in self.data['domain']:
                    list_match = re.split(r'\((\.[a-z]{2,3})\)',domain)
                    if len(list_match) == 1:
                        writer.writerow([domain,self.data['info'],'','100','high'])
                    elif len(list_match) > 1:
                        f_domain = list_match[0]
                        writer.writerow([f_domain,self.data['info'],'','100','high'])
                        match = re.search(r'\.[a-z]{2,3}\s+',f_domain)
                        if match:
                            subdom = f_domain.rstrip(match.group(0))
                            for tld in list_match[1:-1]:
                                ndomain = ''.join([subdom,tld])
                                writer.writerow([ndomain,self.data['info'],'','100','high'])



            if 'url' in self.data:
                for url in self.data['url']:
                    writer.writerow([url,self.data['info'],'','100','high']) 

            if 'ip_address' in self.data:
                for ip in self.data['ip_address']:
                    writer.writerow([ip,self.data['info'],'','100','high'])                     



def file_convert(sourcefile,info,stype,fname):
    with open(sourcefile, 'rU') as src:
        in_data = MATI(src)
        data = in_data.sanitise(info)

    if not fname:
        destfile_kff = sourcefile.replace('_XML.xml','_KFF.csv')
        destfile_tb = sourcefile.replace('_XML.xml','_TB')
        destfile_bro = sourcefile.replace('_XML.xml','_BRO.dat')
    else:
        destfile_kff = os.path.abspath(fname)+'_KFF.csv'
        destfile_tb = os.path.abspath(fname)+'_TB'
        destfile_bro = os.path.abspath(fname)+'_BRO.dat'

    if stype == 'all':
        KFF(data).convert(destfile_kff)
        ThreatBridge(data).convert(destfile_tb)
        BRO(data).convert(destfile_bro)
        
    elif stype == 'KFF':
        KFF(data).convert(destfile_kff)

    elif stype == 'threatbridge':
        ThreatBridge(data).convert(destfile_tb)

    elif stype == 'bro':
        BRO(data).convert(destfile_bro)

def run(inputFileName, inputFilePath, outputBase, deleteQueue):
    validFile = 0
    if inputFileName.endswith('.xml'):
        f = open(inputFilePath)
        for line in f:
            if ((line.find("xml version") != -1) and (line.find("Symantec") != -1) and (line.find("Copyright") != -1)):
                validFile = 1
        f.close()
    if (validFile == 1):
        sourcefile = inputFilePath
        info = (inputFileName.split('.'))[0]
        outputBaseFinal = os.path.join(outputBase,"KFF")
        file_convert(sourcefile,info,"KFF",(os.path.join(outputBaseFinal, info)))
        outputBaseFinal = os.path.join(outputBase,"TB")
        file_convert(sourcefile,info,"threatbridge",(os.path.join(outputBaseFinal, info)))
        outputBaseFinal = os.path.join(outputBase,"Bro")
        file_convert(sourcefile,info,"bro",(os.path.join(outputBaseFinal, info)))
        deleteQueue.put(inputFilePath)

def main():
    print "This module cannot be run standalone"

    
if __name__ == '__main__':
    main()
