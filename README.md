spraygun.sh
(spraygun.py is a work in progress, but will be the same thing more or less)

Spraygun is a wrapper for netexec install here : https://www.netexec.wiki/getting-started/installation/installation-on-unix

--

sudo apt install pipx git

pipx ensurepath

pipx install git+https://github.com/Pennyw0rth/NetExec

--

netexec is the only dependency for this to work.

./spraygun.sh dc-ip users-file pass-file time-between-sprays passwords-per-spray ./spraygun.sh 10.10.10.10 users.txt passwords.txt 20 2

image
