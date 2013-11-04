nagios-sip-plugin
=================

A plugin for [Nagios](http://www.nagios.org/) for checking the status of a SIP server.


## Features

* SIP UDP, TCP and TLS transport protocols.
* Customizable parameters (From URI, Request URI, server address, local UDP port, timeout internal).
* The replied status code can be matched against an expected value to be considered as valid.


## Documentation

The plugin sends an OPTIONS and parses the response status code (or triggers a timeout error).


### Return values

As any Nagios plugin it must behave according to Nagios [API](http://nagios.sourceforge.net/docs/3_0/pluginapi.html):


#### `OK` status

The plugin returns `0` value in two cases:

* `-c` (expected status code) is not set and the server replies any response.
* `-c` is set to a specific value (i.e. "200") and the server replies the same status code.

It also prints to `stdout` a string to be parsed by Nagios:
```
OK:status code = 200
```


#### `WARNING` status

The plugin returns `1` value in case `-c` is set and the response code doesn't match its value.

It also prints to `stdout`:
```
WARNING:Received a 403 but 200 was required
```


#### `CRITICAL` status

The plugin returns `2` value in the following cases:

* No response at all is received from the server in the configured `timeout` interval (`-T` parameter)
* The TCP connection failed.
* An ICMP "port unreachable" message has been received in SIP UDP.
* Error resolving the server IP (when a hostname is used).
* TLS verification error when `-vt` parameter is set and there is not a valid PEM file in the given CA path (`-ca` parameter).
* Other TLS errors.

It also prints to `stdout` (depending on the exact error):
```
CRITICAL:Timeout receiving the response via UDP (Timeout::Error: execution expired)
CRITICAL:Couldn't get the server address 'not-found.org' (SocketError: getaddrinfo: Name or service not known)
CRITICAL:Timeout when connecting the server via TCP (Timeout::Error: execution expired)
...
```


### Commandline options

```
~$ ./nagios-sip-plugin.rb --help

Usage mode:    nagios-sip-plugin.rb [OPTIONS]

  OPTIONS:
    -t (tls|tcp|udp)     :    Protocol to use (default 'udp').
    -s SERVER_IP     :    IP or domain of the server (required).
    -p SERVER_PORT   :    Port of the server (default '5060').
    -r REQUEST_URI   :    Request URI (default 'sip:ping@SERVER_IP:SERVER_PORT').
    -f FROM_URI      :    From URI (default 'sip:nagios@SERVER_IP').
    -c SIP_CODE      :    Expected status code (i.e: '200'). If null then any code is valid.
    -T SECONDS       :    Timeout in seconds (default '2').
    -vt              :    Verify server's TLS certificate when using SIP TLS (default false).
    -ca CA_PATH      :    Directory with public PEM files for validating server's TLS certificate (default '/etc/ssl/certs/').

  Homepage:
    https://github.com/ibc/nagios-sip-plugin
```


### Usage example

```
~$ nagios-sip-plugin.rb -t udp -s 9.9.9.9 -p 5060 -r "sip:9999@myserver.org" -f "sip:nagios@myserver.org" -c 200 -T 3
```
```
~$ nagios-sip-plugin.rb -t tcp -s 9.9.9.9 -p 6060
```

## Dependencies

* Ruby 1.8 or 1.9.


## TODO

* Add retransmissions mechanism for SIP UDP transport.
