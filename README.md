# Fotigate-policytable
Create firewall policy table from firewall backup file-Fortigate 1500D
Firewall backup should be taken VDOM basis.
Total firewall backup may not support.
Save the backup file as "InternalRule.txt".
OR 
Change the backup file name in script "f_name" variable (line 6).
Make sure the above backup file is in same folder as the script is running.
Run the script (make sure python 3 is installed) from cmd or double clik the script file.
output file file be generated as "PolicyBase.csv" (or change the name in line 86) in same folder.
