<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Project 4: CS 5700 Fundamentals of Computer Networking: David Choffnes, Ph.D.</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Homepage for David Choffnes, Ph.D., Associate Professor in Computer Science, Executindex="-1" href="https://david.choffnes.com/rec.php">Extracurricular</a></li>
<li role="presentation"><a role="menuitem" tabindex="-1" href="https://david.choffnes.com/news.php">News</a></li>
</ul>

</li>

<li ><a href="press.php">PRESS</a></li>

<li class="dropdown ">
<a id="drop1" href="#" role="button" class="dropdown-toggle" data-toggle="dropdown"><span style="color:red">JOIN</span><b class="caret"></b></a>
<ul class="dropdown-menu" role="menu" aria-labelledby="drop1">
<li role="presentation"><a role="menuitem" tabindex="-1" hrB file</a>, <a href="10MB.log">10 MB file</a>, <a href="50MB.log">50 MB file</a>.
</p><p>
<h2>High Level Requirements</h2>
You goal is to write a program called <i>rawhttpget</i> that takes one command line parameter
(a URL), downloads the associated web page or file, and saves it to the current directory.
The command line syntax for this program is:
</p><p>
./rawhttpget [URL]
</p><p>
An example invocation of the program might look like this:
</p><p>
./rawhttpget http://david.choffnes.com/classes/cs4700sp22/project4.php
</p><p>
Throgram, you will need to create two raw sockets: one for receiving packets and one for
sending packets. The receive socket must be of type SOCK_RAW/IPPROTO_TCP; the send socket must be
of type SOCK_RAW/IPPROTO_RAW. The reason you need two sockets has to do with some quirks of the Linux kernel.
The kernel will not deliver any packets to sockets of type SOCK_STREAM IPPROTO_RAW, thus your code will
need to bind to the IPPROTO_IP interface to receive packets. However, since you are required to
implement TCP and IP, you must send on a SOCK_RAW/IPPROTO_RAW socket.
</p><p>
There are many tutorials online for doing raw socket programming. I recommend
<a href="http://www.binarytides.com/raw-sockets-c-code-linux/">Silver Moon's tutorial</a> as 
a place to get started. That tutorial is in C; Python also has native support for raw socket
programming. However, <b>not all languages support raw socket programming</b>. Since many of
you program in Java, I will allow the use of the <a href="http://www.savarese.com/software/rocksaw/">
RockSaw Library</a>, which enables raw ceive that packet,
the kernel generates a TCP RST packet to let the sender know that the packet is invalid. However, in your
case, your program is using a raw socket, and thus the kernel has no idea what TCP port you are using. So,
the kernel will erroneously respond to packets destined for your program with TCP RSTs. You don't want
the kernel to kill your remote connections, and thus you need to instruct the kernel to drop outgoing
TCP RST packets. You will need to recreate this rule each time your reboot your machine/VM.
</p><p>
<h2>Debugging</h2>
Debugging raw socket code can be very challenging. You will need to get comfortable with 
<a href="http://www.wireshark.org/">Wireshark</a>
in order to debug your code. Wireshark is a packet sniffer, and can parse all of the relevent fields
from TCP/IP headers. Using Wireshark, you should be able to tell if you are formatting outgoing
packets correctly, and if you are correctly parsing incoming packets.
</p><p>
<h2>Language</h2>
You can write your code in whatever language you choose, as long as your code compicript">
    _uacct = "UA-2830907-1";
    urchinTracker();
    </script-->
    </body>
    <div class="navbar-footer-grey">
    <hr>
    <p>David Choffnes, Associate Professor, Khoury College of Computer Sciences, Northeastern University. &copy; 2021<br>
    Last updated
    <!-- #BeginDate format:Am1 -->February 28, 2022<!-- #EndDate -->.
    </p>
    </div>
    </html>

