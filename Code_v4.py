#! /usr/bin/python3

import sys
import os
#from prettytable import PrettyTable

f_name = 'InternalRule.txt'


def address(file_name):
 table_add = []
 table_ip=[]
 
 start1 = "firewall address"
 end1 = "end"
 nxt1 = "next"  
 sig1='edit'
 sig4='subnet'
 
 wrd1=''
 wrd2=''
 
 file_cp = open(file_name)
 
 while True:
    read_l = file_cp.readline()
    if start1 in read_l: 
      break
 
 while not ((end1 in read_l)&(len(read_l)==4)):
    read_l = file_cp.readline()
	 
    if sig1 in read_l:
       wrd1 = (read_l.split(sig1,1)[1]).strip("\n")
	   
    if sig4 in read_l:
       wrd2 = (read_l.split(sig4,1)[1]).strip("\n")
	   
    if ((nxt1 in read_l) & (len(read_l)==9)):
      table_add.append(wrd1)
      table_ip.append(wrd2)
      wrd1=''
      wrd2=''
 
 print('Done')
 
 file_cp.close()
 
 return (table_add,table_ip)

print ("Hello Fortinet")
start = "config firewall policy"
end = "end"
nxt = "next"
#KEYs
key1='edit'
key2='name'
key3='srcintf'
key4='srcaddr'
key5='dstintf'
key6='dstaddr'
key7='action'
key8='service'
key9='logtraffic'
key10='status'

#TABLE
#table = PrettyTable (['ID','Name','SrcINT','SrcIP','DstINT','DstIP','Action','Service','Log','Status'])
title = "No#,Name,SrcINT,SrcIP,S_IP,DstINT,DstIP,D_IP,Action,Service,Log,Status"
a1=""
a2=""
a3=""
a4=""
a4_1=""
a5=""
a6=""
a6_1=""
a7=""
a8=""
a9=""
a10=""
s_ip=[]
d_ip=[]

db=address(f_name)

file = open(f_name)

output = open('PolicyBase.csv', 'w')
output.write(title + '\n')

while True:
  line = file.readline()
  if start in line: 
    print('start')
    break

#print ('Done2 next loop')
while not ((end in line)&(len(line)==4)):
  line = file.readline()

  if key1 in line:
    a1 = (line.split(key1,1)[1]).strip("\n")
  if key2 in line:
    a2 = (line.split(key2,1)[1]).strip("\n")
  if key3 in line:
    a3 = (line.split(key3,1)[1]).strip("\n")
  if key4 in line:
    a4 = (line.split(key4,1)[1]).strip("\n")
    a4_1 = a4.split()
    i=0
    while(i<len(a4_1)):
      j=0
      while (j<len(db[0])):
        if a4_1[i] in db[0][j]:
          s_ip.append(db[1][j])
          i=i+1
          break        
		  
        else:
          j=j+1
          if (j==len(db[0])):
             s_ip.append(a4_1[i])
             i=i+1
     	
  if key5 in line:
    a5 = (line.split(key5,1)[1]).strip("\n")
  if key6 in line:
    a6 = (line.split(key6,1)[1]).strip("\n")
    a6_1 = a6.split()
    i=0
    while(i<len(a6_1)):
      j=0
      while (j<len(db[0])):
        if a6_1[i] in db[0][j]:
          d_ip.append(db[1][j])
          i=i+1
          break        
		  
        else:
          j=j+1
          if (j==len(db[0])):
             d_ip.append(a6_1[i])
             i=i+1
     	
  if key7 in line:
    a7 = (line.split(key7,1)[1]).strip("\n")
  if key8 in line:
    a8 = (line.split(key8,1)[1]).strip("\n")
  if key9 in line:
    a9 = (line.split(key9,1)[1]).strip("\n")
  if key10 in line:
    a10 = (line.split(key10,1)[1]).strip("\n")

  if ((nxt in line) & (len(line)==9)):
    row=",".join((a1,a2,a3,a4,str(s_ip),a5,a6,str(d_ip),a7,a8,a9,a10))
    #print(row)
    output.write(row + '\n')
    #print('lock me')
    a1=""
    a2=""
    a3=""
    a4=""
    a4_1=""
    a5=""
    a6=""
    a6_1=""
    a7=""
    a8=""
    a9=""
    a10=""
    row=""
    s_ip=[]
    d_ip=[]

  
print("end of line")

file.close()
output.close()
#print(table)
#################################################
#Version 2
#Remap the Firewall policy to a table
#destination IP mapping not working bcs of VIPs
#################################################
