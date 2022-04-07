all:
		sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
		chmod u+x rawhttpget
		vi +':wq ++ff=unix' rawhttpget