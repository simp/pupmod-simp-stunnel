[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-stunnel.svg)](https://travis-ci.org/simp/pupmod-simp-stunnel) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - A Puppet module for managing stunnel](#module-description)
3. [Setup - The basics of getting started with pupmod-simp-stunnel](#setup)
    * [What pupmod-simp-stunnel affects](#what-simp-stunnel-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with stunnel](#beginning-with-stunnel)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## This is a SIMP module
This module is a component of the
[System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our
[JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP)
and visit our [developer wiki](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).

## Module Description

This module sets up stunnel and allows the creation of stunnel connections for
services.

## Setup

### What simp stunnel affects

`simp/stunnel` will install the latest version of stunnel, ensure the service is
running, generate the stunnel user, manage /etc/stunnel/stunnel.conf,
/etc/rc.d/init.d/stunnel, a chroot directory, and if `simp/iptables` is
installed and  $use_iptables is set to true, will manage the iptables required
for stunnel.

### Setup Requirements

`simp/stunnel` requires the `simp/rsync` module to add a service-based stunnel
connection.

### Beginning with stunnel

You can set up stunnel on a node by:

```puppet
include stunnel
```

or 

```yaml
---
classes:
  - stunnel
```

## Usage

### I want to add a connection to the stunnel server

    # Add an stunnel client entry for rsync.
    stunnel::add { 'rsync':
      connect => ['stunnel.server.int:8730'],
      accept  => '127.0.0.1:873'
    }

### I want to build a connection on the stunnel server

    # Add an stunnel client entry for rsync.
    stunnel::add { 'rsync':
      client  => false,
      connect => ['873'],
      accept  => '8730'
    }

## Reference

### Public Classes
* stunnel
* stunnel::add

### `stunnel`

#### Parameters

* `chroot`: The location of the chroot jail. Do NOT make this anything under
/var/run.  Type: Absolute Path.  Default: '/var/stunnel'.

* `key`: Path and name of the private SSL key file.  Type: Absolute Path. 
Default: /etc/pki/private/${::fqdn}.pem.

* `cert`: Path and name of the public SSL certificate.  Type: Absolute Path.
Default: /etc/pki/public/${::fqdn}.pub.

* `ca_source`: Since stunnel runs in a chroot, you need to copy the appropriate
CA certificates in from an external source.  This should be the full path to a
directory containing hashed versions of the CA certificates.  Type: Absolute
Path.  Default: '/etc/pki/cacerts'.

* `crl_source`: Since stunnel runs in a chroot, you need to copy the appropriate
CRL in from an external source.  Type: Absolute Path.  Default: '/etc/pki/crl'.

* `pid`: The PID file. Relative to the chroot jail! Let the startup script
handle it by default.  Type: Absolute Path.  Default:
'/var/run/stunnel/stunnel.pid'.

* `setuid`: The user stunnel should run as.  Type: String.  Default: 'stunnel'.

* `setgid`: The group stunnel should run as.  Type: String.  Default: 'stunnel'.

* `stunnel_debug`: The debug level for logging.  Type: String.  Default: 'err'.

* `syslog`: Whether or not to log to syslog.  Type: Boolean.  Default: true.

* `compression`: The compression type to use for this service. Anything other
than 'zlib' and 'rle' is ignored.  Type: ['zlib'|'rle'].  Default: None.

* `egd`: If set, is the path to the Entropy Gathering Daemon socket used to feed
the OpenSSL RNG.  Type: Absolute Path.  Default: false.

* `engine`: If $egd is set, sets the Hardware Engine to be used.  Type: String.
Default: auto.

* `engine_ctrl`: If set, $egd is set, sets the Hardware Engine Control
parameters.  Type: String.  Default: false.

* `fips`:  If true, set the fips global option.  We don't enable FIPS mode by
default since we want to be able to use TLS1.2.  This has no effect on
RHEL/CentOS 6 or earlier due to stunnel not accepting the fips option in that
version of stunnel.  Type: Boolean.  Default: hiera('use_fips',false).

* `output`: If set, provides the path to a log output file to use.  Type:
Absolute Path.  Default: false.

* `rnd_bytes`: The number of bytes to read from the random seed file.  Type:
Integer. Default: false.

* `rnd_file`: If set, provides the path to the random seed data file.  Type:
Absolute Path. Default: false.

* `rnd_overwrite`: If set, Stunnel should overwrite the random seed file with
new random data. Type: Boolean.  Default: false.

* `socket_options`: If populated, provides an array of socket options of the
form '^(a|l|r):.+=.+(:.+)?$'.  Type: Array of Strings.  Default: [].

* `use_haveged`: If true, include haveged to assist with entropy generation.
Type: Boolean. Default: true.

* `use_simp_pki`: If true, use the SIMP PKI module for key management.  Note:
This module needsthe pki::copy method from the SIMP pki module but does not need
to have SIMP actuallly manage the keys.  Type: Boolean.  Default: true.

### `stunnel::add`

* `name` : The service name. Valid Option: String.

* `accept`:  Address and port upon which to accept connections.  For a client,
this is generally localhost.  For a server, it should be whichever external
address is appropriate.  If this is omitted, then connections are accepted on
all addresses. Valid Options: String [hostname/ip:port].

  Examples:
```puppet
    '1.2.3.4:3000'
    '3000'
```

* `connect`:  Address and port to which to forward connections.  For a client,
this is the port of the stunnel server.  For the stunnel server, this is the
listening port of the tunneled service.  See stunnel.conf(5) for more
information. Valid Options: Array of [hostname/ip:port] Entries.

  Examples:
```puppet
    ['my.server:3000','my.server2:3001']
    ['my.server:3000']
    ['3000']
```

* `client`: Whether this instance of stunnel should behave as a client. Valid
Options: Boolean.  Default: true.

* `cert`: Path and name of the public SSL certificate.  Valid Options: Absolute
Path Default: $::stunnel::cert.

* `ca_path`: Path to the OpenSSL compatible CA certificates. Note, this path is
relative to the chroot path if set and is expected to be a directory.  Valid
Options: Absolute Path Default: /etc/pki/cacerts.

* `client_nets`: Set this if you don't want to allow all IP addresses to access
this encrypted channel. This only makes sense for servers.

  Example:
```puppet
 stunnel::add ('rsync':
   accept       => '873',
   connect_addr => ['1.2.3.4:8730']
 }
```

* `ciphers`: OpenSSL compatible array of ciphers to allow on the system.  Valid
Options: Array Default: ['HIGH','-SSLv2'].

* `crl_path`: Path to the OpenSSL compatible CRL directory.  Valid Options:
Absolute Path Default: /etc/pki/crl.

* `curve`: The ECDH curve name to use. To get a list of supported curves use:
openssl ecparam -list_curves on your *client*.  This option is only valid on
RHEL/CentOS 7+.  Valid Options: String. Default: None.

* `failover`: The failover strategy for multiple connect targets. Valid Options:
[rr|prio].  Default: rr.

* `key`: Path and name of the private SSL key file.  Valid Options: Absolute
Path.  Default: $::stunnel::key.

* `sni`: See the 'sni' option documentation in stunnel. This option is only
valid on RHEL/CentOS 7+. Valid Options:
[service_name|service_name:server_name_pattern].  Default: None.

* `ssl_version`: Dictate the SSL version that can be used on the system. You
only get one choice from the options listed above. This default, combined with
the default $ciphers, the system will only negotiate at TLSv1.1 or higher.
Valid Options: String. Allowed Values (RHEL6): [all|SSLv2|SSLv3|TLSv1] Allowed
Values (RHEL7): [all|SSLv2|SSLv3|TLSv1|TLSv1.1|TLSv1.2] Default: None (let the
system decide).

* `options`: The OpenSSL library options.  Valid Options: Array. Default: None.

* `verify`: Level of mutual authentication to perform.  Valid Options: Integer.
(see below) Default: 2.

```shell
RHEL 6 Options:
  level 1 - verify peer certificate if present
  level 2 - verify peer certificate
  level 3 - verify peer with locally installed certificate
  default - no verify

RHEL 7 Options:
  level 0 - Request and ignore peer certificate.
  level 1 - Verify peer certificate if present.
  level 2 - Verify peer certificate.
  level 3 - Verify peer with locally installed certificate.
  level 4 - Ignore CA chain and only verify peer certificate.
  default - No verify
```

* `ocsp`: The OCSP responder to use for certificate validation.  Valid Options:
URL Default: None.

* `ocsp_flags`: The OCSP server flags.  Valid Options: 'NOCERTS', 'NOINTERN
NOSIGS', 'NOCHAIN', 'NOVERIFY', 'NOEXPLICIT', 'NOCASIGN', 'NODELEGATED',
'NOCHECKS', 'TRUSTOTHER', 'RESPID_KEY', 'NOTIME'.  Default: [].

* `local`: The outgoing IP to which to bind. By default, stunnel binds to all
interfaces.  Valid Options: IP Address Default: None.

* `protocol`: The application protocol to negotiate SSL. Valid Options:
cifs|connect|imap|nntp|pgsql|pop3|proxy|smtp], proxy only working on RHEL/CentOS
7+. Default: None.

* `protocol_authentication`: Authentication type for protocol negotiations.
Valid Options: [basic|NTLM] Default: None.

* `protocol_host`: The destination address for protocol negotiations.  Valid
Options: Hostname or IP Address Default: None.

* `protocol_password`: The password for protocol negotiations.  Valid Options:
String. Default: None.

* `protocol_username`: The username for protocol negotiations.  Valid Options:
String. Default: None.

* `delay`: Delay DNS lookup for 'connect' option Valid Options: Boolean.
Default: false.

* `engine_num`: The engine number from which to read the private key.  This
option is only supported on RHEL/CentOS 7+.  Valid Options: Integer. Default:
None.

* `pty`: Reserve and assign a pty to a program that is run by stunnel
inetd-style using the exec option.  Valid Options: Boolean.  Default: false.

* `renegotiation`: Support SSL renegotiation.  Valid Options: Boolean.  Default:
true.

* `reset`: Attempt to use TCP RST flag to indicate an error.  Valid Options:
Boolean.  Default: true.

* `retry`: Reconnect a connect+exec session after it has been disconnected.
Valid Options: Boolean.  Default: false.

* `session_cache_size`: The maximum number of internal session cache entries.
Set to 0 for unlimited (not advised).  This option is only valid on RHEL/CentOS
7+.  Valid Options: Integer.  Default: None.

* `session_cache_timeout`: The number of seconds to keep cached SSL sessions.
Corresponds to the 'session_timeout' variable in RHEL/CentOS 6.  Valid Options:
Integer.  Default: None.

* `stack`: Thread stack size in bytes.  Valid Options: Integer.  Default: None.

* `timeout_busy`: Time to wait for expected data in seconds.  Valid Options:
Integer.  Default: None.

* `timeout_close`: Time to wait for close notify in seconds.  Valid Options:
Integer.  Default: None.

* `timeout_connect`: Time to wait for a remote host connection in seconds.
Valid Options: Integer.  Default: None.

* `timeout_idle`: Time to keep an idle connection in seconds.  Valid Options:
Integer.  Default: None.

## Limitations

This module is only designed to work in RHEL or CentOS 6 and 7. Any other
operating systems have not been tested and results cannot be guaranteed.

# Development

Please see the
[SIMP Contribution Guidelines](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP).

General developer documentation can be found on
[Confluence](https://simp-project.atlassian.net/wiki/display/SD/SIMP+Development+Home).
Visit the project homepage on [GitHub](https://simp-project.com),
chat with us on our [HipChat](https://simp-project.hipchat.com/),
and look at our issues on  [JIRA](https://simp-project.atlassian.net/).
