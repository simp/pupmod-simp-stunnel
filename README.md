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
/etc/rc.d/init.d/stunnel, a chroot directory, and if  $firewall is set to true,
will manage the iptables required for stunnel.

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
    stunnel::connection { 'rsync':
      connect => ['stunnel.server.int:8730'],
      accept  => '127.0.0.1:873'
    }

### I want to build a connection on the stunnel server

    # Add an stunnel client entry for rsync.
    stunnel::connection { 'rsync':
      client  => false,
      connect => ['873'],
      accept  => '8730'
    }

## Reference

### Public Classes
* stunnel
* stunnel::connection

### `stunnel`

### `stunnel::connection`

Example:
```puppet
 stunnel::connection ('rsync':
   accept       => '873',
   connect      => ['1.2.3.4:8730']
 }
```

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
