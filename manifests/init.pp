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
# [*key*]
#   Type: Absolute Path
#   Default: /etc/pki/private/${::fqdn}.pem
#
#   Path and name of the private SSL key file.
#
# [*cert*]
#   Type: Absolute Path
#   Default: /etc/pki/public/${::fqdn}.pub
#
#   Path and name of the public SSL certificate.
#
# [*ca_source*]
#   Type: Absolute Path
#   Default: '/etc/pki/cacerts'
#     Since stunnel runs in a chroot, you need to copy the appropriate
#     CA certificates in from an external source.
#
#     This should be the full path to a directory containing hashed versions of
#     the CA certificates.
#
# [*crl_source*]
#   Type: Absolute Path
#   Default: '/etc/pki/crl'
#     Since stunnel runs in a chroot, you need to copy the appropriate
#     CRL in from an external source.
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
# [*use_haveged*]
#   Type: Boolean
#   Default: true
#
#   If true, include haveged to assist with entropy generation.
#
# [*use_simp_pki*]
#   Type: Boolean
#   Default: true
#
#   If true, use the SIMP PKI module for key management.
#   Note: This module needs the pki::copy method from the SIMP pki module but
#         does not need to have SIMP actuallly manage the keys.

# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class stunnel (
  $chroot = '/var/stunnel',
  $key = "/etc/pki/private/${::fqdn}.pem",
  $cert = "/etc/pki/public/${::fqdn}.pub",
  $ca_source = '/etc/pki/cacerts',
  $crl_source = '/etc/pki/crl',
  $pid = '/var/run/stunnel/stunnel.pid',
  $setuid = 'stunnel',
  $setgid = 'stunnel',
  $stunnel_debug = 'err',
  $syslog = true,
  $compression = false,
  $egd = false,
  $engine = 'auto',
  $engine_ctrl = false,
  $fips = defined('$::use_fips') ? { true => $::use_fips, default => hiera('use_fips', false) },
  $output = false,
  $rnd_bytes = false,
  $rnd_file = false,
  $rnd_overwrite = false,
  $socket_options = [],
  $use_haveged = true,
  $use_simp_pki = defined('$::use_simp_pki') ? { true => $::use_simp_pki, default => hiera('use_simp_pki', true) }
) {
  if ( str2bool($::selinux_enforced) ) or !($chroot or str2bool($::selinux_enforced)) {
    $_chroot = false
  }
  else {
    $_chroot = $chroot
  }

  if $_chroot { validate_absolute_path($_chroot) }
  validate_absolute_path($key)
  validate_absolute_path($cert)
  validate_absolute_path($ca_source)
  validate_absolute_path($crl_source)
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
  validate_bool($use_haveged)

  compliance_map()

  if $use_simp_pki {
    include '::pki'
  }

  if $use_haveged {
    include '::haveged'
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
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    source  => 'puppet:///modules/stunnel/stunnel',
    tag     => 'firstrun',
    notify  => [
      Exec['stunnel_chkconfig_update'],
      Service['stunnel']
    ],
    require => Package['stunnel']
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

  if $_chroot {
    # The _chroot directory
    file { $_chroot:
      ensure  => 'directory',
      owner   => 'root',
      group   => $setgid,
      mode    => '0770',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    # The following two entries are required to be able to properly resolve
    # hosts using the _chroot directory.
    file { "${_chroot}/etc":
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    file { "${_chroot}/etc/resolv.conf":
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      source  => 'file:///etc/resolv.conf',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    file { "${_chroot}/etc/nsswitch.conf":
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      source  => 'file:///etc/nsswitch.conf',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    file { "${_chroot}/etc/hosts":
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      source  => 'file:///etc/hosts',
      tag     => 'firstrun',
      require => Package['stunnel']
    }

    file { "${_chroot}/var":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0644'
    }

    file { "${_chroot}/var/run":
      ensure => 'directory',
      owner  => $setuid,
      group  => $setgid,
      mode   => '0644'
    }

    file { "${_chroot}/var/run/stunnel":
      ensure => 'directory',
      owner  => $setuid,
      group  => $setgid,
      mode   => '0644'
    }

    file { "${_chroot}/etc/pki":
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0640'
    }

    file { "${_chroot}/etc/pki/cacerts":
      source  => "file://${ca_source}",
      group   => $setgid,
      recurse => true,
      notify  => Service['stunnel']
    }

    File["${_chroot}/etc/resolv.conf"] -> Service['stunnel']
    File["${_chroot}/etc/nsswitch.conf"] -> Service['stunnel']
    File["${_chroot}/etc/hosts"] -> Service['stunnel']
    File["${_chroot}/var/run"] -> Service['stunnel']
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
