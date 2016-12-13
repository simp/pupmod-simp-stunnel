# == Class stunnel::install
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
# * Nick Markowski <nmarkowswki@keywcorp.com>
#
class stunnel::install inherits stunnel {
  assert_private()

  group { $::stunnel::setgid:
    ensure    => 'present',
    allowdupe => false,
    gid       => '600',
    tag       => 'firstrun'
  }

  user { $::stunnel::setuid:
    ensure     => 'present',
    allowdupe  => false,
    gid        => '600',
    uid        => '600',
    home       => '/var/run/stunnel',
    managehome => false,
    membership => 'inclusive',
    shell      => '/sbin/nologin',
    tag        => 'firstrun'
  }

  package { 'stunnel':
    ensure  => 'latest',
    tag     => 'firstrun',
    require => ["User[${::stunnel::setuid}]","Group[${::stunnel::setgid}]"]
  }
}
