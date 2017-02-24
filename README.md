[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-stunnel.svg)](https://travis-ci.org/simp/pupmod-simp-stunnel) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#this-is-a-simp-module)
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

This module is optimally designed for use within a larger SIMP ecosystem, but it
can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be
managed from the Puppet server.
* In the future, all SIMP-managed security subsystems will be disabled by
default and must be explicitly opted into by administrators.  Please review
*simp/simp_options* for details.


## Module Description

This module sets up [stunnel](https://www.stunnel.org/index.html) and allows the creation of stunnel connections for
services.

## Setup

### What simp stunnel affects

*simp/stunnel* will manage:

* The latest version of stunnel
* Ensure the service is running
* The stunnel user
* /etc/stunnel/stunnel.conf,
* /etc/rc.d/init.d/stunnel
* A stunnel chroot directory
* If $firewall is set to true, will manage the *simp/iptables* firewall
settings required for stunnel.

### Setup Requirements

*simp/stunnel* requires the *simp/rsync* module to add a service-based stunnel
connection.

### Beginning with stunnel

You can set up stunnel on a node by:

```puppet
include stunnel
```

## Usage

### I want to add a connection to the stunnel server

```puppet
stunnel::connection { 'rsync':
  connect => ['stunnel.server.int:8730'],
  accept  => '127.0.0.1:873'
}
```

### I want to build a connection on the stunnel server

```puppet
stunnel::connection { 'rsync':
  client  => false,
  connect => ['873'],
  accept  => '8730'
}
```

## Reference

### Public Classes
* [`stunnel`](#stunnel): Main Class
* [`stunnel::connection`](#stunnelconnection): Creates an Stunnel connection on client or server
* [`stunnel::config`](#stunnelconfig): Configures Stunnel
* [`stunnel::service`](#stunnelservice): Manages Stunnel Service

### Private Classes
* `stunnel::install`: Installs Stunnel Packages

### `stunnel`

#### Parameters

##### pki:

  Toggle for Managing Certificates.
  * Valid Options: Boolean or simp.
  * Default: `false`.

  * Options:
    ```
    * If 'simp', include SIMP's pki module and use pki::copy to manage
      application certs in /etc/pki/simp_apps/stunnel/x509

    * If true, do *not* include SIMP's pki module, but still use pki::copy
      to manage certs in /etc/pki/simp_apps/stunnel/x509

    * If false, do not include SIMP's pki module and do not use pki::copy
      to manage certs.  You will need to appropriately assign a subset of:
         * app_pki_dir
         * app_pki_key
         * app_pki_cert
         * app_pki_ca
         * app_pki_ca_dir
    ```

##### app_pki_external_source:

  If pki is set to simp, this is the directory from which certs will be copied
via pki::copy.
  * Valid Options: String containing a directory.
  * Default: `/etc/pki/simp/x509`

##### app_pki_dir:

  Controls the source of certs in the chroot, and the basepath of $app_pki_key,
$app_pki_cert, $app_pki_ca, $app_pki_ca_dir, and $app_pki_crl.
  * Valid Options: String containing a directory.
  * Default: `/etc/pki/simp_apps/stunnel/x509`.

    ```
    Even when using a chroot, stunnel needs the certs to reside **outside** of the chroot path
    ```

##### app_pki_key:

  Path and name of the private SSL key file.
  * Valid Options: String containing a certificate file location.
  * Default: `${app_pki_dir}/private/${facts['fqdn']}.pem`.

##### app_pki_cert:

  Path and name of the public SSL certificate.
  * Valid Options: String containing a certificate file location.
  * Default: `${app_pki_dir}/public/${facts['fqdn']}.pub`.

##### app_pki_ca_dir:

  Directory external from the stunnel chroot to copy the CA certificates from.
This should be the full path to a directory containing hashed versions of the CA
certificates.
  * Valid Options: String containing a directory.
  * Default: `${app_pki_dir}/cacerts`

##### app_pki_crl:

  Directory external from the stunnel chroot to copy the Certificate Revocation
  List from.
  * Valid Options: String containg a directory.
  * Default: `${app_pki_dir}/crl`

##### setuid:

  The user stunnel should run as.
  * Valid Options: String.
  * Default: `stunnel`

##### setgid:

  The group stunnel should run as.
  * Valid Options: String.
  * Default: `stunnel`

##### syslog:

  Whether or not to log to syslog.
  * Valid Options: Boolean.
  * Default: `simp_options` or `false`.

##### fips:

  Set the fips global option.
  * Valid Options: Boolean.
  * Default: `simp_options` or `false`.

    ```
    This has no effect on EL < 7 due to stunnel not accepting the fips option in
    that version of stunnel.
    ```

##### haveged:

  Include the SIMP ``haveged`` module to assist with entropy
generation.
  * Valid Options: Boolean.
  * Default: simp_options or false.

### `stunnel::connection`

##### name:

  The service name.
  * Valid Options: String.

##### connect:

  Address and port to which to **forward** connections.
  * Valid Options: Array of ports.

    ```NOTE
    * For a client, this is the port of the stunnel server

    * For the stunnel server, this is the listening port of the tunneled
      service

    * Just a port indicates that you wish to listen on all interfaces

    Examples:
        * ['my.server:3000','my.server2:3001']
        * ['my.server:3000']
        * ['3000']
    ```

##### accept:

  Address and port upon which to **accept** connections.
  * Valid Options: Array of Ports.

    ```
    * For a client, this is generally 'localhost'

    * For a server, it should be whichever external address is appropriate

    * If this is omitted, then connections are accepted on all addresses

    Examples:
        * '1.2.3.4:3000'
        * '3000'
    ```

##### client:

  Indicates that this connection is a client connection.
  * Valid Options: true or false.
  * Default: `true`.

##### failover:

  The failover strategy for multiple connect targets.
  * Valid Options: rr and prio .
  * Default: `rr`.

##### sni:

  See the 'sni' option documentation in ``stunnel(8)``.
  * Valid Options: String.
  * Default: `undef`.

    ```
    This option is only valid on EL 7+
    ```

##### app_pki_key:

  Path and name of the private SSL key file.
  * Valid Options: String containing a directory.
  * Default: `undef`.

##### app_pki_cert:

  Path and name of the public SSL certificate.
  * Valid Options: String containing a directory.
  * Default: `undef`.

##### app_pki_cacert:

  Path to the OpenSSL compatible CA certificates.
  * Valid Options: String containing a directory.
  * Default: `/etc/pki/simp_apps/stunnel/`.

    ```
    This path is relative to the chroot path if set and is expected to be
    a directory
    ```

##### app_pki_crl:

  Path to the OpenSSL compatible CRL directory.
  * Valid Options: String containing a directory.
  * Default: `/etc/pki/simp_apps/stunnel/`.

##### openssl_cipher_suite:

  OpenSSL compatible array of ciphers to allow on the
system.
  * Valid Options: Array.
  * Default: `['HIGH','SSLv2']`.

##### curve:

  The ECDH curve name to use. To get a list of supported curves use:
``openssl ecparam -list_curves`` on your client.
  * Valid Options: String.
  * Default: `undef`.

    ```
    This option is only valid on EL 7+
    ```

##### ssl_version:

  Dictate the SSL version that can be used on the system.
  * Valid Options: String containing the SSL version.
  * Default: `undef`.

    ```
    This default, combined with the default '$ciphers', will only negotiate at
    TLSv1. or higher
    ```

##### options:

  The OpenSSL library options.
  * Valid Options: Array.
  * Default: `undef`.

##### verify:

  Level of mutual authentication to perform.
  * Valid Options: Integer.
  * Default: `2`.

    ```
    RHEL 6 Options:
      * level 1 - verify peer certificate if present
      * level 2 - verify peer certificate
      * level 3 - verify peer with locally installed certificate
      * default - no verify
    RHEL 7 Options:
      * level 0 - Request and ignore peer certificate.
      * level 1 - Verify peer certificate if present.
      * level 2 - Verify peer certificate.
      * level 3 - Verify peer with locally installed certificate.
      * level 4 - Ignore CA chain and only verify peer certificate.
      * default - No verify
    ```

##### ocsp:

  The OCSP responder to use for certificate validation.
  * Valid Options: URI.
  * Default: `undef`.

##### ocsp_flags:

  The OCSP server flags.
  * Valid Options: Array.
  * Default: `[]`.

##### local:

  The outgoing IP to which to bind.
  * Valid Options: IP Address.
  * Default: `undef`.

    ```
    By default, stunnel binds to all interfaces
    ```

##### protocol:

  The application protocol to negotiate SSL.
  * Valid Options: String.
  * Default: `undef`.

    ```
    RHEL/CentOS 6:  [cifs|connect|imap|nntp|pgsql|pop3|smtp]
    RHEL/CentOS 7+: [cifs|connect|imap|nntp|pgsql|pop3|proxy|smtp]
    ```

##### protocol_authentication:

  Authentication type for protocol negotiations.
  * Valid Options: basic or NTLM.
  * Default: `undef`.

##### protocol_host:

  The destination address for protocol negotiations.
  * Valid Options: String.
  * Default: `undef`.

##### protocol_password:

  The password for protocol negotiations.
  * Valid Options: String.
  * Default: `undef`.

##### protocol_username:

  The username for protocol negotiations.
  * Valid Options: String.
  * Default: `undef`.

##### delay:

  Delay DNS lookup for ``connect`` option.
  * Valid Options: true or false.
  * Default: `false`.

##### engine_num:

  The engine number from which to read the private key.
  * Valid Options: undef.
  * Default: `undef`.

    ```
    This option is only supported on RHEL/CentOS 7+
    ```

##### pty:

  Reserve and assign a pty to a program that is run by stunnel inetd-style
using the ``exec`` option.
  * Valid Options: true or false.
  * Default: `false`.

##### renegotiation:

  Support SSL renegotiation.
  * Valid Options: true or false.
  * Default: `true`.

##### reset:

  Attempt to use TCP ``RST`` flag to indicate an error.
  * Valid Options: true or false.
  * Default: `true`.

##### retry:

  Reconnect a ``connect+exec`` session after it has been disconnected.
  * Valid Options: true or false.
  * Default: `false`.

##### session_cache_size:

  The maximum number of internal session cache entries.
  * Valid Options: Integer.
  * Default: `undef`.

    ```
    Set to 0 for unlimited (**not advised**)

    This option is only valid on EL 7+
    ```

##### session_cache_timeout:

  The number of seconds to keep cached SSL sessions.
  * Valid Options: Integer.
  * Default: `undef`.

    ```
    Corresponds to the session_timeout variable in EL 6
    ```

##### stack:

  Thread stack size in **bytes**.
  * Valid Options: Integer.
  * Default: `undef`.

##### timeout_busy:

  Time to wait for expected data in **seconds**.
  * Valid Options: Integer.
  * Default: `undef`.

##### timeout_close:

  Time to wait for close notify in **seconds**.
  * Valid Options: Integer.
  * Default: `undef`.

##### timeout_connect:

  Time to wait for a remote host connection in **seconds**.
  * Valid Options: Integer.
  * Default: `undef`.

##### timeout_idle:

  Time to keep an idle connection in **seconds**.
  * Valid Options: Integer.
  * Default: `undef`.

##### trusted_nets:

  Set this if you don't want to allow all IP addresses to access
this connection. This value only works properly for servers.
  * Valid Options: CIDR Address.
  * Default: `127.0.0.1`.

##### firewall:

  Include the SIMP ``iptables`` module to manage the firewall.
  * Valid Options: true or false.
  * Default: `false`.

##### tcpwrappers:

  Include the SIMP ``tcpwrappers`` module to manage tcpwrappers.
  * Valid Options: true or false.
  * Default: `false`.

### stunnel::config

#### Parameters

##### chroot:

  The location of the chroot jail.
  * Valid Options: Absolute Path.
  * Default: `/var/stunnel`.

    ```
    Do NOT make this anything under var/run
    ```

##### pki:

  If ``simp``, include SIMP's ``pki`` module and use ``pki::copy`` to manage
application certs in ``/etc/pki/simp_apps/stunnel/x509``.
  * Valid Options: simp, true or false.
  * Default: `$::stunnel::pki`.

    ```
    * If true: do *not* include SIMP's pki module, but still use
      pki::copy to manage certs in /etc/pki/simp_apps/stunnel/x509

    * If false, do not include SIMP's pki module and do not use
      pki::copy to manage certs. You will need to appropriately assign a
      subset of:
        * app_pki_dir
        * app_pki_key
        * app_pki_cert
        * app_pki_ca_dir
    ```

##### app_pki_external_source:

  If pki = ``simp`` or ``true``, this is the directory from which certs. will be
copied, via ``pki::copy``.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_external_source`.

    ```
    If pki = false, this variable has no effect.
    ```

##### app_pki_dir:

  The source of certs in the chroot, and the basepath of
``$app_pki_key``, ``$app_pki_cert``, ``$app_pki_ca``, ``$app_pki_ca_dir``, and
``$app_pki_crl``.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_dir`.

    ```
    Even when using a chroot, stunnel needs the certs to reside outside of the
    chroot path.
    ```

##### app_pki_key:

  Path and name of the private SSL key file.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_key`.

##### app_pki_cert:

  Path and name of the public SSL certificate.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_cert`.

##### app_pki_ca_dir:

  Since stunnel runs in a chroot, you need to copy the appropriate CA
certificates in from an external source.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_ca_dir`.

    ```
    This should be the full path to a directory containing **hashed**
    versions of the CA certificates.
    ```

##### app_pki_crl:

  Since stunnel runs in a chroot, you need to copy the appropriate CRL in from
an external source.
  * Valid Options: Absolute Path.
  * Default: `$::stunnel::app_pki_crl`.

##### pid:

  The PID file, relative to the chroot jail.
  * Valid Options: String.
  * Default: `/var/run/stunnel/stunnel.pid`.

##### setuid:

  The user stunnel should run as.
  * Valid Options: String.
  * Default: `$::stunnel::setuid`.

##### setgid:

  The group stunnel should run as.
  * Valid Options: String.
  * Default: `$::stunnel::setgid`.

##### stunnel_debug:

  The debug level for logging.
  * Valid Options: String>.
  * Default: `err`.

##### syslog:

  Enable logging to syslog.
  * Valid Options: true or false.
  * Default: `$::stunnel::syslog`.

##### compression:

  The compression type to use for this service.
  * Valid Options: `zlib` or `rle`.
  * Default: `undef`.

##### egd:

  The path to the Entropy Gathering Daemon socket used to feed the OpenSSL
Random Number Generator.
  * Valid Options: String.
  * Default: `undef`.

##### engine:

  If ``$egd`` is set, sets the Hardware Engine to be used.
  * Valid Options: String.
  * Default: `auto`.

##### engine_ctrl:

  If ``$egd`` is set, sets the Hardware Engine Control parameters.
  * Valid Options: String.
  * Default: `undef`.

##### fips:

  Set the ``fips`` global option.
  * Valid Options: true or false.
  * Default: `$::stunnel::fips`.

    ```
    We don't enable FIPS mode by default since we want to be able to use
    TLS1.2

    This has no effect on EL < 7 due to stunnel not accepting the fips option in
    that version of stunnel
    ```

##### output:

  The path to a log output file to use.
  * Valid Options: Absolute Path.
  * Default: `undef`.

##### rnd_bytes:

  The number of bytes to read from the random seed file.
  * Valid Options: Integer.
  * Default: `undef`.

##### rnd_file:
  The path to the random seed data file.
  * Valid Options: Absolute Path.
  * Default: `undef`.

##### rnd_overwrite:
  Overwrite the random seed file with new random data.
  * Valid Options: true or false.
  * Default: `false`.

##### socket_options:

  Places `socket = ` options at the end of the stunnel config file.
  * Valid Options: Array.
  * Default: `[]`.

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
