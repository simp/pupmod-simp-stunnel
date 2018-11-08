[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/stunnel.svg)](https://forge.puppetlabs.com/simp/stunnel)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/stunnel.svg)](https://forge.puppetlabs.com/simp/stunnel)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-stunnel.svg)](https://travis-ci.org/simp/pupmod-simp-stunnel)

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

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our
[JIRA](https://simp-project.atlassian.net/).

Please read our [Contribution Guide](http://simp-doc.readthedocs.io/en/stable/contributors_guide/index.html).

This module is optimally designed for use within a larger SIMP ecosystem, but it
can be used independently:

* When included within the SIMP ecosystem, security compliance settings will be
  managed from the Puppet server.

* All SIMP-managed security subsystems are disabled by default and must be
  explicitly opted into by administrators.  Please review
  [simp/simp_options](https://github.com/simp/pupmod-simp-simp_options) for
  details.


## Module Description

This module sets up [stunnel](https://www.stunnel.org/index.html) and allows
the creation of stunnel connections for services.

**IMPORTANT**

| Please use the ``stunnel::connection`` define instead of including the
| ``stunnel`` class directly.
|
| The main ``stunnel`` class is deprecated and will be removed in a future release.
|
| The main ``stunnel`` class manages the **global** stunnel configuration and
| this was deemed to be too risky for use across services that are not related.


## Setup

### What simp stunnel affects

*simp::stunnel* will manage:

* The latest version of stunnel
* Ensure the service is running
* Stunnel configuration files and daemons for each of your services
* A stunnel chroot directory for each of your services
* If ``$firewall`` is set to ``true``, will manage the
  [simp/iptables](https://github.com/simp/pupmod-simp-iptables) firewall
  settings required for stunnel.

### Setup Requirements

There are no special requirements for using this module.

### Beginning with stunnel

You can set up stunnel for a particular service using the following code:

```ruby
stunnel::instance { 'service_name':
  accept => 873,
  connect => ['1.2.3.4:8730']
}
```

This will create ``/etc/stunnel/stunnel_service_name.conf`` and spawn a system
service ``stunnel_service_name``.


## Usage

### I want to add a connection **to** the stunnel server

```ruby
stunnel::instance { 'my_service':
  connect => ['stunnel.server.int:8730'],
  accept  => '127.0.0.1:873'
}
```

### I want to build a connection **on** the stunnel server

```ruby
stunnel::connection { 'my_service':
  client  => false,
  connect => [873],
  accept  => 8730
}
```

## Reference

Please see the ``puppet strings`` [generated documentation](https://github.com/simp/pupmod-simp-stunnel/tree/master/doc) for a full reference.

## Limitations

This module is only designed to work in RHEL or CentOS 6 and 7. Any other
operating systems have not been tested and results cannot be guaranteed.

# Development

Please read our [Contribution Guide](http://simp-doc.readthedocs.io/en/stable/contributors_guide/index.html).

Visit the project homepage on [GitHub](https://simp-project.com)
and look at our issues on  [JIRA](https://simp-project.atlassian.net/).
