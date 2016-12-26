# Global stunnel options
#
# @param chroot
#   The location of the chroot jail
#
#   * Do **NOT** make this anything under ``/var/run``
#
# @param app_pki_dir
#   If ``$pki`` is true, certs will be copied to this location for stunnel
#   to use
#
#   * **NOTE:** Even when using a chroot, stunnel needs the certs to reside
#     **outside** of the chroot path
#
# @param app_pki_key
#   Path and name of the private SSL key file
#
# @param app_pki_cert
#   Path and name of the public SSL certificate
#
# @param app_pki_ca_dir
#   Since stunnel runs in a chroot, you need to copy the appropriate CA
#   certificates in from an external source
#
#   * This should be the full path to a directory containing **hashed**
#   versions of the CA certificates
#
# @param app_pki_crl
#   Since stunnel runs in a chroot, you need to copy the appropriate CRL in
#   from an external source
#
# @param pid
#   The PID file
#
#   * Relative to the chroot jail!
#   * Let the startup script handle it by default
#
# @param setuid
#   The user stunnel should run as
#
# @param setgid
#   The group stunnel should run as
#
# @param stunnel_debug
#   The debug level for logging
#
# @param syslog
#   Enable logging to syslog
#
# @param compression
#   The compression type to use for this service
#
# @param egd
#   The path to the Entropy Gathering Daemon socket used to feed the OpenSSL
#   Random Number Generator
#
# @param engine
#   If ``$egd`` is set, sets the Hardware Engine to be used
#
# @param engine_ctrl
#   If ``$egd`` is set, sets the Hardware Engine Control parameters
#
# @param fips
#   Set the ``fips`` global option
#
#   * We don't enable FIPS mode by default since we want to be able to use
#     TLS1.2
#
#   * **NOTE:** This has no effect on EL < 7 due to stunnel not accepting the
#     fips option in that version of stunnel
#
# @param output
#   The path to a log output file to use
#
# @param rnd_bytes
#   The number of bytes to read from the random seed file
#
# @param rnd_file
#   The path to the random seed data file
#
# @param rnd_overwrite
#   Overwrite the random seed file with new random data
#
# @param socket_options
#
# @param pki
#   Use the SIMP ``pki`` module for key management
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowski@keywcorp.com>
#
class stunnel::config (
  Stdlib::Absolutepath           $app_pki_dir    = $::stunnel::app_pki_dir,
  Stdlib::Absolutepath           $app_pki_key    = $::stunnel::app_pki_key,
  Stdlib::Absolutepath           $app_pki_cert   = $::stunnel::app_pki_cert,
  Stdlib::Absolutepath           $app_pki_ca_dir = $::stunnel::app_pki_ca_dir,
  Stdlib::Absolutepath           $app_pki_crl    = $::stunnel::app_pki_crl,
  Stdlib::Absolutepath           $chroot         = '/var/stunnel',
  Stdlib::Absolutepath           $pid            = '/var/run/stunnel/stunnel.pid',
  String                         $setuid         = $::stunnel::setuid,
  String                         $setgid         = $::stunnel::setgid,
  String                         $stunnel_debug  = 'err',
  Optional[Enum['zlib','rle']]   $compression    = undef,
  Optional[String]               $egd            = undef,
  String                         $engine         = 'auto',
  Optional[String]               $engine_ctrl    = undef,
  Optional[Stdlib::Absolutepath] $output         = undef,
  Optional[Integer]              $rnd_bytes      = undef,
  Optional[Stdlib::Absolutepath] $rnd_file       = undef,
  Boolean                        $rnd_overwrite  = false,
  Array[String]                  $socket_options = [],
  Boolean                        $syslog         = $::stunnel::syslog,
  Boolean                        $fips           = $::stunnel::fips,
  Boolean                        $pki            = $::stunnel::pki
) inherits stunnel {

  if $facts['selinux_current_mode'] and $facts['selinux_current_mode'] != 'disabled' {
    $_chroot = undef
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

  file { '/etc/stunnel':
    ensure  => 'directory',
    owner   => 'root',
    group   => $setgid,
    mode    => '0750',
    recurse => true,
    tag     => 'firstrun',
  }

  concat { '/etc/stunnel/stunnel.conf':
    owner          => 'root',
    group          => 'root',
    mode           => '0600',
    ensure_newline => true,
    warn           => true
  }

  concat::fragment { '0_stunnel_global':
    order   => 1,
    target  => '/etc/stunnel/stunnel.conf',
    content => template('stunnel/stunnel.erb')
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
