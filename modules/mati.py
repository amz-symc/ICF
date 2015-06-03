import sys,os
import csv
import time
import xml.etree.ElementTree as ET
import re
import uuid
import datetime

__author__ = 'Ahmed Zaki'
__copyrights__ = 'Symantec UK Ltd 2015'
__version__ = "1.1.0"
__email__ = "ahmed_zaki@symantec.com"
__status__ = "Beta"

class MATI(object):

    def __init__(self,srcfile):
        self.data = ET.parse(srcfile)


    def sanitise(self,info):
        i_dict = {}
        root = self.data.getroot() 
        text = root.find('report_text')
        name = text.find('report_title').text
        metadata = root.find('metadata')
        info = '/'.join([info,metadata.find('threat_domains').text])

        i_dict['campaigns'] = []
        i_dict['actors'] = []

        for campaign in metadata.find('campaigns'):
            cname = campaign.find('campaign_name').text
            if not cname:
                continue
            i_dict['campaigns'].append(cname)

        for actor in metadata.find('actors'):
            aname = actor.find('actor_name').text
            if not aname:
                continue
            i_dict['actors'].append(aname)

        i_dict['files'] = []
        for x_file in metadata.find('files'):
            if not x_file.find('file_md5').text:
                break

            if x_file.find('file_mal_flag').text == 'y':
                j_file = {}
                j_file['file_md5'] = x_file.find('file_md5').text
                if x_file.find('file_name') is not None:
                    if x_file.find('file_name').text:
                        j_file['file_name'] = x_file.find('file_name').text

                i_dict['files'].append(j_file)



        indicators = metadata.find('extracted_indicators')
        for indicator in indicators:
            i_type = indicator.find('indicator_type')
            i_val  = indicator.find('indicator')

            if not i_val.text:
                continue 

            if i_type.text == 'file_md5':
                continue 

            if i_type.text not in i_dict:
                i_dict[i_type.text] = []
            
            i_dict[i_type.text].append(i_val.text.replace('[.]','.'))

        i_dict['info'] = info.encode("ascii","ignore")
        i_dict['reportname'] = name.encode("ascii","ignore")

        return i_dict

class IOC(object):

    def __init__(self,data):
        self.data = data
        iocguid = uuid.uuid4()
        todaydate = time.strftime("%Y-%m-%d")
        todaytime = time.strftime("%H:%M:%S")
        today = 'T'.join([todaydate,todaytime])
        self.root = ET.Element('ioc',{'id':str(iocguid),'last-modified': str(today), 'xmlns:xsi':"http://www.w3.org/2001/XMLSchema-instance" \
            ,'xmlns:xsd':"http://www.w3.org/2001/XMLSchema", 'xmlns':"http://schemas.mandiant.com/2010/ioc"})
        self.sdesc = ET.SubElement(self.root,'short_description')
        self.desc = ET.SubElement(self.root,'description')
        self.auth = ET.SubElement(self.root,'authored_by')
        self.auth.text = "Symantec"
        self.date = ET.SubElement(self.root,'authored_date')
        self.date.text = today
        self.iocdef = ET.SubElement(self.root,'definition')
        iguid = uuid.uuid4()
        operator = "OR"
        idict = {"operator":operator,"id":str(iguid)}
        self.indicator = ET.SubElement(self.iocdef,'Indicator',idict)
        self.tree = ET.ElementTree(self.root)

    def addindicator(self,data,dtype):
        if dtype not in ['file_name', 'file_md5', 'domain', 'uri']:
            return

        indctr_guid = uuid.uuid4()
        indctr_cond = 'is'

        if dtype is 'file_name':
            ctxdict = {"document": 'FileItem', "search":'FileItem/FileName', "type": 'symcir'}
            condict = {"type":'string'}

        elif dtype is 'file_md5':
            ctxdict = {"document": 'FileItem', "search":'FileItem/Md5sum', "type": 'symcir'}
            condict = {"type":'md5'}

        elif dtype in ['domain','uri']:
            ctxdict = {"document": 'UrlHistoryItem', "search":'UrlHistoryItem/URL', "type": 'symcir'}
            condict = {"type":'string'} 
            indctr_cond = 'contains'


        idict = {'id': str(indctr_guid),'condition': indctr_cond}
        indctr = ET.SubElement(self.indicator,'IndicatorItem',idict)
        context = ET.SubElement(indctr,'Context',ctxdict) 
        content = ET.SubElement(indctr,'Content',condict)
        content.text = data



    def convert(self,destfile):

        if self.data['files']:
            for i_file in self.data['files']:
                for key,val in i_file.iteritems():
                    self.addindicator(val,key)

        if 'url' in self.data:
            for i_url in self.data['url']:
                self.addindicator(i_url,'uri')

        if 'domain' in self.data:
            for i_domain in self.data['domain']:
                list_match = re.split(r'\((\.[a-z]{2,3})\)',i_domain)
                if len(list_match) == 1:
                    self.addindicator(i_domain,'domain')
                elif len(list_match) > 1:
                    f_domain = list_match[0]
                    self.addindicator(f_domain,'domain')
                    match = re.search(r'\.[a-z]{2,3}\s+',f_domain)
                    if match:
                        subdom = f_domain.rstrip(match.group(0))
                        for tld in list_match[1:-1]:
                            ndomain = ''.join([subdom,tld])
                            self.addindicator(ndomain,'domain')

        self.desc.text = '\n'.join(['Report: {0}'.format(self.data['reportname']),'Actors: {0}'.format('-'.join(self.data['actors']))])
        info = '/'.join([self.data['info'],'-'.join(self.data['campaigns'])])
        self.sdesc.text = info
        self.tree.write(destfile,xml_declaration=True,encoding='us-ascii')


class KFF(object):

    def __init__(self,data):
        self.data = data
        self.headers = ['MD5']

    def convert(self,destfile):
        if not self.data['files']:
            return

        with open(destfile,'wb+') as f:
            writer = csv.writer(f, delimiter=',')
            writer.writerow(self.headers)
            for i_file in self.data['files']:
                    writer.writerow([i_file['file_md5']])



class BRO(object):

    def __init__(self,data):
        self.data = data
        #fields indicator   indicator_type  meta.source meta.desc  meta.severity   meta.confidence
        self.headers = ''.join(['#fields indicator\t','indicator_type\t','meta.source\t','meta.desc\t','meta.severity\t','meta.confidence\n'])


    def convert(self,destfile):

        with open(destfile, 'wb+') as f:
            f.write(self.headers)
            if self.data['files']:
                for bfile in self.data['files']:
                    f.write('\t'.join([bfile['file_md5'],'Intel::FILE_HASH','MATI',self.data['reportname'],'high','100','\n']))

            if 'url' in self.data:
                for url in self.data['url']:
                    f.write('\t'.join([url,'Intel::URL','MATI',self.data['reportname'],'high','100','\n']))

            if 'domain' in self.data:
                for domain in self.data['domain']:
                    f.write('\t'.join([domain,'Intel::DOMAIN','MATI',self.data['reportname'],'high','100'+'\n']))

            if 'ip_address' in self.data:
                for ip in self.data['ip_address']:
                    f.write('\t'.join([ip,'Intel::ADDR','MATI',self.data['reportname'],'high','100'+'\n'])) 

            if 'email_from_address' in self.data:
                for email in self.data['email_from_address']:
                    f.write('\t'.join([email,'Intel::EMAIL','MATI',self.data['reportname'],'high','100'+'\n']))




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

            if self.data['files']:
                for tbfile in self.data['files']:
                        writer.writerow([tbfile['file_md5'],self.data['info'],'','100','high'])

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



def file_convert(sourcefile,info,stype):
    with open(sourcefile, 'rU') as src:
        in_data = MATI(src)
        data = in_data.sanitise(info)

    s_fname = os.path.split(sourcefile)[-1].rstrip('_XML.xml')
    destfile_kff = '-'.join([s_fname,'KFF.csv'])
    destfile_tb = '-'.join([s_fname,'TB'])
    destfile_bro = '-'.join([s_fname,'BRO.dat'])
    destfile_ioc = '-'.join([s_fname,'IOC.ioc'])



    if stype == 'all':
        KFF(data).convert(destfile_kff)
        ThreatBridge(data).convert(destfile_tb)
        BRO(data).convert(destfile_bro)
        IOC(data).convert(destfile_ioc)
        
    elif stype == 'KFF':
        KFF(data).convert(destfile_kff)

    elif stype == 'threatbridge':
        ThreatBridge(data).convert(destfile_tb)

    elif stype == 'bro':
        BRO(data).convert(destfile_bro)

    elif stype == 'ioc':
        IOC(data).convert(destfile_ioc)

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
        file_convert(sourcefile,info,"KFF")
        outputBaseFinal = os.path.join(outputBase,"TB")
        file_convert(sourcefile,info,"threatbridge")
        outputBaseFinal = os.path.join(outputBase,"Bro")
        file_convert(sourcefile,info,"bro")
        outputBaseFinal = os.path.join(outputBase,"IOC")
        file_convert(sourcefile,info,"ioc")
        deleteQueue.put(inputFilePath)

def main():
    print "This module cannot be run standalone"

    
if __name__ == '__main__':
    main()
