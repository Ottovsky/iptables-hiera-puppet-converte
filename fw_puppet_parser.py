#!/usr/bin/env python
'''
Created on Oct 17, 2014

@author: aotto
'''
import sys, getopt

puppet_dictionary = {'-A':'chain', '-p':'proto', '-j':'jump',
'--to-destination':'todest', '--to-source':'tosource', '--dport':'dport', '-d':'destination', '-s':'source', '--state':'state','--ctstate':'ctstate',
 '-o':'outiface', '-i':'iniface', '--reject-with':'reject','--sport':'sport','--ports':'port','--seconds':'rseconds','--name':'rname','--icmp-type':'icmp_match'}
single_dictionary = {'--set':'recent','--update':'recent','--rcheck':'recent'}
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
                    
   # print iptables_content
    
    for i in range(len(iptables_content)):
        if(iptables_content[i][0][0] == '*'):
            fw_table = ['table' , iptables_content[i][0].replace("*", "")]
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
                    
    #print fw_puppet
    tmp = 0;
    for fw_item in fw_puppet:
        
        if (fw_item[0] == 'table' and tmp != 0):
            tmp = tmp + 1
            text_buffer.append("}" + 2 * "\n" + "firewall { '%03d"%tmp + " rule ':\n")
        elif(fw_item[0] == 'table' and tmp == 0):
            tmp = tmp + 1
            text_buffer.append("firewall { '%03d"%tmp + " rule ':\n")
        elif (fw_item[0] == "dport"):
            fw_item[1] = "['" + fw_item[1].replace(":", "-").replace(",", "','") + "']"
        elif (fw_item[0] == "sport"):
            fw_item[1] = "['" + fw_item[1].replace(":", "-").replace(",", "','") + "']"
        elif (fw_item[0] == "port"):
            fw_item[1] = "['" + fw_item[1].replace(":", "-").replace(",", "','") + "']"
        elif(fw_item[0] == "state" and len(fw_item[1].split(",")) > 1):
            fw_item[1] = "['" + fw_item[1].replace(",", "','") + "']"
        elif(fw_item[0] == "ctstate" and len(fw_item[1].split(",")) > 1):
            fw_item[1] = "['" + fw_item[1].replace(",", "','") + "']"
        elif((fw_item[0] == "todest") or (fw_item[0] == "tosource") or (fw_item[0] == "destination") or (fw_item[0] == "source")):
            fw_item[1] = "'" + fw_item[1]+ "'"
        elif(fw_item[0] == "jump" and ((fw_item[1]=='ACCEPT') or (fw_item[1]=='REJECT') or (fw_item[1]=='DROP'))):
            fw_item[0] = "action"
            fw_item[1] = fw_item[1].lower()
        text_buffer.append(fw_item[0] + "=>" + fw_item[1] + ",\n")
    text_buffer.append("}")
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
