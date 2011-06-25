tftpd-cgi
=========
A simple tftp server implementation capable of serving CGI scripts from a specified cgi directory (defaults to cgi/).

This would be useful for serving different boot configurations for PXE based on IP or MAC address.

Configuration is currently done at the top of `tftpd-cgi.py`.

TODO
-----
* The WRITE/put operation
* Command-line args
* CGI timeout
* Proper error handling. Use the messages and codes defined at the end of [RFC 1350](http://tools.ietf.org/html/rfc1350 "RFC 1350")

Usage
----
Simply run `python tftpd-cgi` or `./tftpd-cgi.py` to start the server. Remember you usually need elevated privileges to bind to ports under 1024, and TFTP uses port 69 by default.

This ships with a basic cgi script: "cgi/test". It currently outputs a simple message and the client HOST:PORT when retrieved.

With a simple tftp client, I test the cgi functionality like this:

	echo 'get cgi/test' | tftp 127.0.0.1; cat test && rm test