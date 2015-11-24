#!/usr/bin/env python
'''
Created on Oct 17, 2014

@author: aotto

comments: aotto@cern.ch
work with RHEL 6.0
'''
import sys, getopt
from _audit import PTRDIFF_MAX
#dictonary for entries with specific value
puppet_dictionary = {'-A':'chain', '-p':'proto', '-j':'jump',
'--to-destination':'todest', '--to-source':'tosource', '--dport':'dport', '-d':'destination', '-s':'source', '--state':'state','--ctstate':'ctstate', '--hitcount':'rhitcount',
 '-o':'outiface', '-i':'iniface', '--reject-with':'reject','--sport':'sport','--ports':'port','--seconds':'rseconds','--name':'rname','--icmp-type':'icmp'}
#entries which corresponds to one value in puppet
single_dictionary = {'--set':'recent','--update':'recent','--rcheck':'recent'}
#entries, which are set as true if specified
true_dictionary = {'--rsource':'rsource','--rttl':'rttl'}

def usage():
    print "The program is taking iptables-save  output from a file and parse it to puppet configuration."
    print "Arguments: -i iptables-save file  -o destination for output file"    
    sys.exit(2)

def puppet_parser(input_file, output_file):
    
    try:
        iptables_save = open(input_file,'r')
    except IOError:
        print "Error: File does not appear to exist."
        usage()
        
    try:    
        iptables_puppet=open(output_file,'w')
    except IOError:
        print "Error: Incorrect parameter or destination file."
        usage()
        
    iptables_content = []
    fw_puppet = []
    fw_chain_accept = []
    fw_chain_drop = []
    text_buffer = []
    cord=[]
    for i in iptables_save.readlines():
        iptables_content.append(i.split())
        
        
    #Detecting exclamation mark for negated entries   
    for i in range(len(iptables_content)):
        for k in range(len(iptables_content[i])):
            if (iptables_content[i][k]=="!"):
                cord.append(i)
                if(iptables_content[i][k-1][0]=='-'):
                    iptables_content[i][k+1]="!"+iptables_content[i][k+1] 
                    #print     iptables_content[i][k+1]
                else:
                    iptables_content[i][k-1]="!"+iptables_content[i][k-1]
                    #print iptables_content[i][k-1]
    for i in cord:
        iptables_content[i].remove("!") #removing useles ! from list             
                    
    #print iptables_content
    
    for i in range(len(iptables_content)):
        if(iptables_content[i][0][0] == '*'):
            fw_table = ['table' , iptables_content[i][0].replace("*", "")]
            fw_chain_accept.append(fw_table)
            fw_chain_drop.append(fw_table)
        if(iptables_content[i][0][0] == ':' and ( iptables_content[i][1]=='ACCEPT' or iptables_content[i][1]=='-')):             
            fw_chain_accept.append(iptables_content[i])
        if(iptables_content[i][0][0] == ':' and  iptables_content[i][1]=='DROP'):             
            fw_chain_drop.append(iptables_content[i])  
        if(iptables_content[i][0][0] == '-'):
            fw_puppet.append(fw_table)
            for index in range(len(iptables_content[i])):
                if (iptables_content[i][index] in puppet_dictionary) and (iptables_content[i][index] not in single_dictionary) and (iptables_content[i][index] not in true_dictionary):
                    fw_puppet.append([puppet_dictionary[iptables_content[i][index]] , iptables_content[i][index + 1]])
                    index = index + 1
                elif (iptables_content[i][index] not in puppet_dictionary) and (iptables_content[i][index] in single_dictionary) and (iptables_content[i][index] not in true_dictionary):
                    fw_puppet.append([single_dictionary[iptables_content[i][index]] , iptables_content[i][index].replace("-","")])
                    index = index + 1
                elif (iptables_content[i][index] not in puppet_dictionary) and (iptables_content[i][index] not in single_dictionary) and (iptables_content[i][index]  in true_dictionary):
                    fw_puppet.append([true_dictionary[iptables_content[i][index]] , 'true'])
                    index = index + 1
    #print fw_chain_accept   
    #print fw_chain_drop
    
    #creating firewall chain rules
    if (len(fw_chain_accept)>=2):
        text_buffer.append("iptables::pre_rules::firewall_chain:\n")
    
        for chain_item in fw_chain_accept:
            chain_item[0]=chain_item[0].replace(":","")
            if chain_item[0] == 'table':
                table_type = chain_item[1]
            else:
                text_buffer.append("    '"+chain_item[0]+":"+table_type+":IPv4':\n"+"        ensure: 'present'\n")
                if(chain_item[1]!="-"):
                    text_buffer.append("        policy: '"+chain_item[1].lower()+"'\n")
                
    if (len(fw_chain_drop)>=2):
        text_buffer.append("iptables::post_rules::firewall_chain:\n")
    
        for chain_item in fw_chain_drop:
            chain_item[0]=chain_item[0].replace(":","")
            if chain_item[0] == 'table':
                table_type = chain_item[1]
            else:
                text_buffer.append("    '"+chain_item[0]+":"+table_type+":IPv4':\n"+"        ensure: 'present'\n")
                if(chain_item[1]!="-"):
                    text_buffer.append("        policy: '"+chain_item[1].lower()+"'\n")
        
        
    fw_tmp = []
    ptr = 0
    prot_ok = False
    
    #overcoming puppet feature, where default protocol for firewall rule is tcp, changing to all
    for fw_item in fw_puppet:
            
            if fw_item[0]=='proto':
                    prot_ok = True
            if (fw_item[0]=='table' and ptr != 0 and prot_ok == False):
                    index = ptr
                    #print "index false %d"%index
                    fw_tmp.append(['proto','all'])                    
            if (fw_item[0]=='table' and ptr != 0 and prot_ok == True):
                    index = ptr
                    #print "index true %d"%index
                    prot_ok = False
            fw_tmp.append(fw_item)                    
            ptr += 1
    
    #print fw_tmp 
    fw_puppet = fw_tmp
    #creating ip tables entries
    tmp = 0;
    for fw_item in fw_puppet:
        if (fw_item[0] != 'table'):
            fw_item[1]="'"+fw_item[1]+"'"        
        if (fw_item[0] == 'table' and tmp != 0):
            tmp = tmp + 1
            text_buffer.append(1 * "\n" + "    '%03d"%tmp + " rule ':\n")
        if(fw_item[0] == 'table' and tmp == 0):
            fw_item[1]="'"+fw_item[1]+"'"
            tmp = tmp + 1
            text_buffer.append("iptables::pre_rules::firewall_rules:\n    '%03d"%tmp + " rule ':\n")
        if (fw_item[0] == "dport"):
            fw_item[1] = "[" + fw_item[1].replace(":", "-").replace(",", "' , '") + "]"
        if (fw_item[0] == "sport"):
            fw_item[1] = "[" + fw_item[1].replace(":", "-").replace(",", "' , '") + "]"
        if (fw_item[0] == "port"):
            fw_item[1] = "[" + fw_item[1].replace(":", "-").replace(",", "' , '") + "]"
        if(fw_item[0] == "state" and len(fw_item[1].split(",")) > 1):
            fw_item[1] = "[" + fw_item[1].replace(",", "' , '") + "]"
        if(fw_item[0] == "ctstate" and len(fw_item[1].split(",")) > 1):
            fw_item[1] = "[" + fw_item[1].replace(",", "' , '") + "]"
        if(fw_item[0] == "jump" and ((fw_item[1]=="'ACCEPT'") or (fw_item[1]=="'REJECT'") or (fw_item[1]=="'DROP'"))):
            fw_item[0] = "action"
            fw_item[1] = fw_item[1].lower()
        if(fw_item[0]=='icmp' and fw_item[1]=="'any'"):
            continue
        text_buffer.append("        "+fw_item[0] + ": " + fw_item[1] + "\n")

    for word in text_buffer:
        iptables_puppet.write(word)
    iptables_puppet.close()
    iptables_save.close()
    

    
    
if __name__ == '__main__':
    input=''
    output=''
    try:
        arg = sys.argv[1]
    except IndexError:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError as err:
        print err
        usage()
    for opt, arg in opts:
        if opt == '-h':
           usage()
           sys.exit()
        elif opt in ("-i", "--ifile"):
           input = arg
        elif opt in ("-o", "--ofile"):
           output = arg
           
    puppet_parser(input, output)
    print "[INFO] file parsed."
    sys.exit(2)
