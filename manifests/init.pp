# == Class: stunnel
#
# Set up stunnel.  This needs a public and private key to function.
#
# == Parameters
#
# [*chroot*]
#   Type: Absolute Path
#   Default: '/var/stunnel'
#
#   The location of the chroot jail. Do NOT make this anything under
#   /var/run.
#
# [*pid*]
#   Type: Absolute Path
#   Default: '/var/run/stunnel/stunnel.pid'
#
#   The PID file. Relative to the chroot jail! Let the startup script
#   handle it by default.
#
# [*setuid*]
#   Type: String
#   Default: 'stunnel'
#
#   The user stunnel should run as.
#
# [*setgid*]
#   Type: String
#   Default: 'stunnel'
#
#   The group stunnel should run as.
#
# [*stunnel_debug*]
#   Type: String
#   Default: 'err'
#
#   The debug level for logging.
#
# [*syslog*]
#   Type: Boolean
#   Default: true
#
#   Whether or not to log to syslog.
#
# [*compression*]
#   Type: ['zlib'|'rle']
#   Default: None
#
#   The compression type to use for this service. Anything other than
#   'zlib' and 'rle' is ignored.
#
# [*egd*]
#   Type: Absolute Path
#   Default: false
#
#   If set, is the path to the Entropy Gathering Daemon socket used to
#   feed the OpenSSL RNG.
#
# [*engine*]
#   Type: String
#   Default: auto
#
#   If $egd is set, sets the Hardware Engine to be used.
#
# [*engine_ctrl*]
#   Type: String
#   Default: false
#
#   If set, $egd is set, sets the Hardware Engine Control parameters.
#
# [*fips*]
#   Type: Boolean
#   Default: hiera('use_fips',false)
#
#   If true, set the fips global option.
#   We don't enable FIPS mode by default since we want to be able to use
#   TLS1.2.
#
#   Note: This has no effect on RHEL/CentOS < 7 due to stunnel not accepting
#   the fips option in that version of stunnel.
#
# [*output*]
#   Type: Absolute Path
#   Default: false
#
#   If set, provides the path to a log output file to use.
#
# [*rnd_bytes*]
#   Type: Integer
#   Default: false
#
#   The number of bytes to read from the random seed file.
#
# [*rnd_file*]
#   Type: Absolute Path
#   Default: false
#
#   If set, provides the path to the random seed data file.
#
# [*rnd_overwrite*]
#   Type: Boolean
#   Default: false
#
#   If set, Stunnel should overwrite the random seed file with new
#   random data.
#
# [*socket_options*]
#   Type: Array of Strings
#   Default: []
#
#   If populated, provides an array of socket options of the form '^(a|l|r):.+=.+(:.+)?$'.
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class stunnel (
  $chroot = '/var/stunnel',
  $pid = '/var/run/stunnel/stunnel.pid',
  $setuid = 'stunnel',
  $setgid = 'stunnel',
  $stunnel_debug = 'err',
  $syslog = true,
  $compression = false,
  $egd = false,
  $engine = 'auto',
  $engine_ctrl = false,
  $fips = hiera('use_fips',false),
  $output = false,
  $rnd_bytes = false,
  $rnd_file = false,
  $rnd_overwrite = false,
  $socket_options = []
) {

  if $l_chroot { validate_absolute_path($l_chroot) }
  if $pid { validate_absolute_path($pid) }
  validate_string($setuid)
  validate_string($setgid)
  validate_re($stunnel_debug,'^(.+\.)?.+$')
  validate_bool($syslog)
  validate_array_member($compression, ['zlib', 'rle',false])
  if $egd { validate_absolute_path($egd) }
  if $engine { validate_string($engine) }
  if $engine_ctrl { validate_string($engine_ctrl) }
  if $output { validate_absolute_path($output) }
  if $rnd_bytes { validate_integer($rnd_bytes) }
  if $rnd_file { validate_absolute_path($rnd_file) }
  if $rnd_overwrite { validate_bool($rnd_overwrite) }
  validate_array($socket_options)

  if ( str2bool($::selinux_enforced) ) or !($chroot or str2bool($::selinux_enforced)) {
    $l_chroot = false
  }
  else {
    $l_chroot = $chroot
  }

  concat_build { 'stunnel':
    order   => ['*.conf'],
    target  => '/etc/stunnel/stunnel.conf',
    require => Package['stunnel']
  }

  concat_fragment { 'stunnel+0global.conf':
    content => template('stunnel/stunnel.erb')
  }

  exec { 'stunnel_chkconfig_update':
    command     => '/sbin/chkconfig --del stunnel; /sbin/chkconfig --add stunnel',
    refreshonly => true,
    require     => Package['stunnel']
  }

  file { '/etc/rc.d/init.d/stunnel':
    ensure   => 'present',
    owner    => 'root',
    group    => 'root',
    mode     => '0750',
    source   => 'puppet:///modules/stunnel/stunnel',
    tag      => 'firstrun',
    notify   => [
      Exec['stunnel_chkconfig_update'],
      Service['stunnel']
    ],
    require  => Package['stunnel']
  }


  file { '/etc/stunnel':
    ensure  => 'directory',
    owner   => 'root',
    group   => $setgid,
    mode    => '0750',
    recurse => true,
    tag     => 'firstrun',
    require => Package['stunnel']
  }

  file { '/etc/stunnel/stunnel.conf':
    ensure    => 'present',
    owner     => 'root',
    group     => 'root',
    mode      => '0640',
    notify    => Service['stunnel'],
    require   => Package['stunnel'],
    subscribe => Concat_build['stunnel'],
    tag       => 'firstrun',
    audit     => content
  }

  if $l_chroot {
    # The l_chroot directory
    file { $l_chroot:
      ensure  => 'directory',
      owner   => 'root',
      group   => $setgid,
      mode    => '0770',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    # The following two entries are required to be able to properly resolve
    # hosts using the l_chroot directory.
    file { "${l_chroot}/etc":
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    file { "${l_chroot}/etc/resolv.conf":
      ensure   => 'file',
      owner    => 'root',
      group    => 'root',
      mode     => '0644',
      source   => 'file:///etc/resolv.conf',
      tag      => 'firstrun',
      require  => Package['stunnel']
    }

    file { "${l_chroot}/etc/nsswitch.conf":
      ensure   => 'file',
      owner    => 'root',
      group    => 'root',
      mode     => '0644',
      source   => 'file:///etc/nsswitch.conf',
      tag      => 'firstrun',
      require  => Package['stunnel']
    }

    file { "${l_chroot}/etc/hosts":
      ensure   => 'file',
      owner    => 'root',
      group    => 'root',
      mode     => '0644',
      source   => 'file:////etc/hosts',
      tag      => 'firstrun',
      require  => Package['stunnel']
    }

    file { "${l_chroot}/var":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0644'
    }

    file { "${l_chroot}/var/run":
      ensure => 'directory',
      owner  => $setuid,
      group  => $setgid,
      mode   => '0644'
    }

    pki::copy { "${l_chroot}/etc":
      group  => $setgid,
      notify => Service['stunnel']
    }

    File["${l_chroot}/etc/resolv.conf"] -> Service['stunnel']
    File["${l_chroot}/etc/nsswitch.conf"] -> Service['stunnel']
    File["${l_chroot}/etc/hosts"] -> Service['stunnel']
    File["${l_chroot}/var/run"] -> Service['stunnel']
  }

  group { $setgid:
    ensure    => 'present',
    allowdupe => false,
    gid       => '600',
    tag       => 'firstrun'
  }

  package { 'stunnel':
    ensure => 'latest',
    tag    => 'firstrun'
  }


  service { 'stunnel':
    ensure     => 'running',
    hasrestart => true,
    hasstatus  => true,
    require    =>  [
      File['/etc/rc.d/init.d/stunnel'],
      Package['stunnel']
    ],
    tag        => 'firstrun'
  }

  user { $setuid:
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

}
