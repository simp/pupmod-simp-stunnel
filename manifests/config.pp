# == Class: stunnel
#
# Configure stunnel.
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
# [*app_pki_dir*]
#   Type: Absolute Path
#   Default: /var/stunnel_pki
#
#   If $pki is true, certs will be copied to this location for stunnel
#   to use.  NOTE: Even when using a chroot, stunnel needs the certs
#   to reside outside of the chroot path.
#
# [*app_pki_key*]
#   Type: Absolute Path
#   Default: /etc/pki/private/${::fqdn}.pem
#
#   Path and name of the private SSL key file.
#
# [*app_pki_cert*]
#   Type: Absolute Path
#   Default: /etc/pki/public/${::fqdn}.pub
#
#   Path and name of the public SSL certificate.
#
# [*app_pki_ca_dir*]
#   Type: Absolute Path
#   Default: '/etc/pki/cacerts'
#     Since stunnel runs in a chroot, you need to copy the appropriate
#     CA certificates in from an external source.
#
#     This should be the full path to a directory containing hashed versions of
#     the CA certificates.
#
# [*app_pki_crl*]
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
#   Default: false
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
# [*selinux*]
#   Type: Boolean
#   Default: false
#
#   If true, use the SIMP Selinux module for context enforcement.
#
# [*pki*]
#   Type: Boolean
#   Default: false
#
#   If true, use the SIMP PKI module for key management.
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
# * Nick Markowski <nmarkowski@keywcorp.com>
#
class stunnel::config (
  Stdlib::Absolutepath              $app_pki_dir    = $stunnel::app_pki_dir,
  Stdlib::Absolutepath              $app_pki_key    = $::stunnel::app_pki_key,
  Stdlib::Absolutepath              $app_pki_cert   = $::stunnel::app_pki_cert,
  Stdlib::Absolutepath              $app_pki_ca_dir = $::stunnel::app_pki_ca_dir,
  Stdlib::Absolutepath              $app_pki_crl    = $::stunnel::app_pki_crl,
  Stdlib::Absolutepath              $chroot         = '/var/stunnel',
  Stdlib::Absolutepath              $pid            = '/var/run/stunnel/stunnel.pid',
  String                            $setuid         = $stunnel::setuid,
  String                            $setgid         = $stunnel::setgid,
  Pattern['^(.+\.)?.+$']            $stunnel_debug  = 'err',
  Optional[Enum['zlib','rle']]      $compression    = undef,
  Optional[String]                  $egd            = undef,
  String                            $engine         = 'auto',
  Optional[String]                  $engine_ctrl    = undef,
  Optional[Stdlib::Absolutepath]    $output         = undef,
  Optional[Stdlib::Compat::Integer] $rnd_bytes      = undef,
  Optional[Stdlib::Absolutepath]    $rnd_file       = undef,
  Boolean                           $rnd_overwrite  = false,
  Array[String]                     $socket_options = [],
  Boolean                           $selinux        = $::stunnel::selinux,
  Boolean                           $syslog         = $::stunnel::syslog,
  Boolean                           $fips           = $::stunnel::fips,
  Boolean                           $pki            = $::stunnel::pki
) inherits stunnel {

  if ($selinux)  or !($chroot or $selinux) {
    $_chroot = false
  }
  else {
    $_chroot = $chroot
  }

  if $pki {
    include '::pki'

    file { $app_pki_dir:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755'
    }
    ::pki::copy { $app_pki_dir:
      require => File[$app_pki_dir]
    }
  }

  simpcat_build { 'stunnel':
    order  => ['*.conf'],
    target => '/etc/stunnel/stunnel.conf',
  }

  simpcat_fragment { 'stunnel+0global.conf':
    content => template('stunnel/stunnel.erb')
  }

  file { '/etc/stunnel':
    ensure  => 'directory',
    owner   => 'root',
    group   => $setgid,
    mode    => '0750',
    recurse => true,
    tag     => 'firstrun',
  }

  file { '/etc/stunnel/stunnel.conf':
    ensure    => 'present',
    owner     => 'root',
    group     => 'root',
    mode      => '0640',
    subscribe => Simpcat_build['stunnel'],
    tag       => 'firstrun',
    audit     => content
  }

  if $_chroot {
    # The _chroot directory
    file { $_chroot:
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0770',
      tag    => 'firstrun',
    }

    # The following two entries are required to be able to properly resolve
    # hosts using the _chroot directory.
    file { "${_chroot}/etc":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
      tag    => 'firstrun',
    }

    file { "${_chroot}/etc/resolv.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/resolv.conf',
      tag    => 'firstrun',
    }

    file { "${_chroot}/etc/nsswitch.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/nsswitch.conf',
      tag    => 'firstrun',
    }

    file { "${_chroot}/etc/hosts":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/hosts',
      tag    => 'firstrun',
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
      source  => "file://${app_pki_dir}/pki/cacerts",
      group   => $setgid,
      mode    => '0640',
      recurse => true,
    }
  }

}
