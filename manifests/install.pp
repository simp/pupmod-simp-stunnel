# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Install the Stunnel components
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowswki@keywcorp.com>
#
class stunnel::install inherits ::stunnel {
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
    require => [
      "User[${::stunnel::setuid}]",
      "Group[${::stunnel::setgid}]"
    ]
  }
}
