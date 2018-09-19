# Global stunnel options
#
# @param chroot
#   The location of the chroot jail, if it is not set to `undef`
#   If SELinux is set to Enforced or Permissive, `$chroot` will be
#   set to `undef`. This option only affects `stunnel::connection`.
#
#   * Do **NOT** make this anything under ``/var/run``
#
# @param pki
#   * If ``simp``, include SIMP's ``pki`` module and use ``pki::copy`` to
#     manage application certs in ``/etc/pki/simp_apps/stunnel/x509``
#   * If ``true``, do *not* include SIMP's pki module, but still use
#     ``pki::copy`` to manage certs in ``/etc/pki/simp_apps/stunnel/x509``
#   * If ``false``, do not include SIMP's pki module and do not use
#     ``pki::copy`` to manage certs.  You will need to appropriately assign a
#     subset of:
#       * app_pki_dir
#       * app_pki_key
#       * app_pki_cert
#       * app_pki_ca_dir
#
# @param app_pki_external_source
#   * If pki = ``simp`` or ``true``, this is the directory from which certs
#     will be copied, via ``pki::copy``
#
#   * If pki = ``false``, this variable has no effect
#
# @param app_pki_dir
#   The source of certs in the chroot, and the basepath of ``$app_pki_key``,
#   ``$app_pki_cert``, ``$app_pki_ca``, ``$app_pki_ca_dir``, and
#   ``$app_pki_crl``
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
# @param uid
#   The UID of the stunnel user
#
# @param gid
#   The GID of the stunnel user
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
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::config (
  Variant[Enum['simp'],Boolean]  $pki                     = $::stunnel::pki,
  Stdlib::Absolutepath           $app_pki_dir             = $::stunnel::app_pki_dir,
  String                         $app_pki_external_source = $::stunnel::app_pki_external_source,
  Stdlib::Absolutepath           $app_pki_key             = $::stunnel::app_pki_key,
  Stdlib::Absolutepath           $app_pki_cert            = $::stunnel::app_pki_cert,
  Stdlib::Absolutepath           $app_pki_ca_dir          = $::stunnel::app_pki_ca_dir,
  Stdlib::Absolutepath           $app_pki_crl             = $::stunnel::app_pki_crl,
  Stdlib::Absolutepath           $chroot                  = '/var/stunnel',
  Optional[Stdlib::Absolutepath] $pid                     = undef,
  String                         $setuid                  = $::stunnel::setuid,
  String                         $setgid                  = $::stunnel::setgid,
  Integer                        $uid                     = $::stunnel::uid,
  Integer                        $gid                     = $::stunnel::gid,
  String                         $stunnel_debug           = 'err',
  Optional[Enum['zlib','rle']]   $compression             = undef,
  Optional[String]               $egd                     = undef,
  String                         $engine                  = 'auto',
  Optional[String]               $engine_ctrl             = undef,
  Optional[Stdlib::Absolutepath] $output                  = undef,
  Optional[Integer]              $rnd_bytes               = undef,
  Optional[Stdlib::Absolutepath] $rnd_file                = undef,
  Boolean                        $rnd_overwrite           = false,
  Array[String]                  $socket_options          = [],
  Boolean                        $syslog                  = $::stunnel::syslog,
  Boolean                        $fips                    = $::stunnel::fips
) inherits stunnel {

  include '::stunnel::monolithic'

  ensure_resource('stunnel::account', $setuid,
    {
      'groupname' => $setgid,
      'uid'       => $uid,
      'gid'       => $gid
    }
  )

  if $facts['selinux_current_mode'] and $facts['selinux_current_mode'] != 'disabled' {
    $_chroot = undef
  }
  else {
    $_chroot = $chroot
  }

  if $pki {
    pki::copy { 'stunnel':
      source => $app_pki_external_source,
      pki    => $pki
    }
  }

  # $_legacy_pid is used to kill the old stunnel process set up from a previous
  #   version of this module. It should be set to $_pid, unless $_pid is unset.
  $on_systemd = 'systemd' in $facts['init_systems']

  if $pid =~ Undef {
    if $on_systemd {
      $_foreground = true
    } else {
      $_foreground = undef
    }
    $_pid        = '/var/run/stunnel/stunnel.pid'
    $_legacy_pid = '/var/run/stunnel/stunnel.pid'

  } else {
    $_pid        = $pid
    $_legacy_pid = $pid
  }

  if $_pid and !$on_systemd {
    $_stunnel_piddir = File[dirname($_pid)]
    ensure_resource('file', dirname($_pid),
      {
        'ensure'  => 'directory',
        'owner'   => $setuid,
        'group'   => $setgid,
        'mode'    => '0644',
        'seluser' => 'system_u',
        'selrole' => 'object_r',
        'seltype' => 'stunnel_var_run_t',
      }
    )
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
    content => template('stunnel/connection_conf.erb')
  }

  if $_chroot !~ Undef {
    if $_chroot in ['/',''] {
      fail("stunnel: \$chroot should not be root ('/')")
    }
    if $_chroot =~ /^\/var\/run/ {
      fail("stunnel: \$chroot cannot be under /var/run")
    }

    # The _chroot directory
    file { $_chroot:
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0770'
    }

    # The following two entries are required to be able to properly resolve
    # hosts using the _chroot directory.
    file { "${_chroot}/etc":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755'
    }

    file { "${_chroot}/etc/resolv.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/resolv.conf'
    }

    file { "${_chroot}/etc/nsswitch.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/nsswitch.conf'
    }

    file { "${_chroot}/etc/hosts":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/hosts'
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
      source  => "file://${app_pki_dir}/cacerts",
      group   => $setgid,
      mode    => '0640',
      recurse => true,
    }

    # If we're setting up PKI here, we also need to make sure the
    # correct structure is setup prior to copy or we get errors.
    if $pki {
      Pki::Copy['stunnel'] -> File["${_chroot}/etc/pki/cacerts"]
    }
  }

  # These templates need variables, that's why they are here
  if $on_systemd {
    file { '/etc/systemd/system/stunnel.service':
      ensure  => file,
      content => template('stunnel/connection_systemd.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      notify  => Exec['stunnel daemon reload']
    }
    exec { 'stunnel daemon reload':
      command     => '/usr/bin/systemctl daemon-reload',
      refreshonly => true,
    }

  }
  else {
    if $_pid {
      # The selinux context settings are ignored if SELinux is disabled
      ensure_resource('file', dirname($_pid),
        {
          'ensure'  => 'directory',
          'owner'   => $setuid,
          'group'   => $setgid,
          'mode'    => '0644',
          'seluser' => 'system_u',
          'selrole' => 'object_r',
          'seltype' => 'stunnel_var_run_t',
        }
      )
    }

    file { '/etc/rc.d/init.d/stunnel':
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => template('stunnel/connection_init.erb'),
    }

  }

}
