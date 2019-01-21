# Set up a stunnel connection with a unique configuration and service
#
# NOTE: Since many of the parameters here may need to be modified on a
# case-by-base basis, this defined type uses capabilities presented by the
# ``simplib::dlookup`` function to allow for either global overrides or
# instance-specific overrides.
#
# Global overrides work the same way as classes
# (``stunnel::instance::ssl_version: 'TLSv1.2'``) but will affect **all**
# instances of the defined type that are not specifically overridden as shown
# below.
#
# Instance specific overrides preclude the need for a resource collector in
# that you can place the follwing in Hiera to affect a single instance named
# ``rsync``: ``Stunnel::Instance[rsync]::ssl_version: 'TLSv1.2'``
#
# @example Add an Rsync listener
#  stunnel::instance {'rsync':
#    accept  => 873,
#    connect => ['1.2.3.4:8730']
#  }
#
# * Creates /etc/stunnel/stunnel_managed_by_puppet_rsync.conf
# * Spawns service 'stunnel_managed_by_puppet_rsync' from the configuration
#   file
#
# Any instances created with this defined type will be removed from the system
# if no longer managed to prevent conflicts.
#
# Instances created with versions of the module prior to 6.3.0 may need to be
# independently removed since there is no safe way to remove those files.
#
# @param name [String]
#   The name of the stunnel process.
#
# @param connect
#   Address and port to which to **forward** connections
#
#   * For a client, this is the port of the stunnel server
#   * For the stunnel server, this is the listening port of the tunneled
#     service
#   * Just a port indicates that you wish to listen on all interfaces
#
#   * Examples:
#       * ['my.server:3000','my.server2:3001']
#       * ['my.server:3000']
#       * ['3000']
#
# @param accept
#   Address and port upon which to **accept** connections
#
#   * For a client, this is generally ``localhost``
#   * For a server, it should be whichever external address is appropriate
#       * If this is omitted, then connections are accepted on all addresses
#
#   * Examples:
#       * '1.2.3.4:3000'
#       * '3000'
#
# @param trusted_nets
#   Set this if you don't want to allow all IP addresses to access this
#   connection
#
#   * This only makes sense for servers
#
# @param haveged
#   Include ``haveged`` support when setting up stunnel (highly recommended)
#
# @param firewall
#   Include the SIMP ``iptables`` module to manage the firewall
#
# @param tcpwrappers
#   Include the SIMP ``tcpwrappers`` module to manage tcpwrappers
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
#     versions of the CA certificates
#
# @param app_pki_cacert
#   The path to the full CA certificate for the Stunnel connections
#
# @param app_pki_crl
#   Since stunnel runs in a chroot, you need to copy the appropriate CRL in
#   from an external source
#
# @param chroot
#   The location of the chroot jail. If left unset, and selinux is NOT disabled,
#   it will default to `/var/stunnel_<local bind port>`.
#
#   * Do **NOT** make this anything under ``/var/run``
#
# @param client
#   Indicates that this connection is a client connection
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
# @param openssl_cipher_suite
#   OpenSSL compatible array of ciphers to allow on the system
#
# @param ssl_version
#   Dictate the SSL version that can be used on the system
#
#   * This default, combined with the default ``$ciphers``, will only negotiate
#     at ``TLSv1.1`` or higher
#
# @param options
#   The OpenSSL library options
#
# @param uid
#   The user id of the stunnel user
#
# @param gid
#   The group id of the stunnel group
#
# @param pid Leave undef if no PID is desired. Default on systemd systems.
#
# @param systemd_wantedby Systemd services or targets that want stunnel
#
# @param systemd_requiredby Systemd services or targets that require stunnel
#
# All other configuration options can be found in the stunnel man pages
# @see stunnel.conf(5)
# @see stunnel.conf(8)
#
# @param client
# @param compression
# @param curve
# @param delay
# @param egd
# @param engine
# @param engine_ctrl
# @param engine_num
# @param exec
# @param execargs
# @param failover
# @param local
# @param ocsp
# @param ocsp_flags
# @param output
# @param protocol
# @param protocol_host
# @param protocol_username
# @param protocol_password
# @param protocol_authentication
# @param pty
# @param renegotiation
# @param reset
# @param retry
# @param rnd_bytes
# @param rnd_file
# @param rnd_overwrite
# @param session_cache_size
# @param session_cache_timeout
# @param setuid
# @param setgid
# @param sni
# @param socket_options
# @param stack
# @param stunnel_debug
# @param syslog
# @param timeout_busy
# @param timeout_close
# @param timeout_connect
# @param timeout_idle
# @param verify
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
define stunnel::instance(
  Stunnel::Connect                            $connect,
  Variant[Simplib::Port, Simplib::Host::Port] $accept,
  Boolean                                     $client                  = true,

  Simplib::Netlist                            $trusted_nets            = simplib::dlookup('stunnel::instance', 'trusted_nets', $name, { 'default_value' => simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] }) }),
  Boolean                                     $firewall                = simplib::dlookup('stunnel::instance', 'firewall', $name, { 'default_value' => simplib::lookup('simp_options::firewall', { 'default_value' => false }) }),
  Boolean                                     $haveged                 = simplib::dlookup('stunnel::instance', 'haveged', $name, { 'default_value' => simplib::lookup('simp_options::haveged', { 'default_value' => true }) }),
  Boolean                                     $tcpwrappers             = simplib::dlookup('stunnel::instance', 'tcpwrappers', $name, { 'default_value' => simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }) }),
  Variant[Enum['simp'],Boolean]               $pki                     = simplib::dlookup('stunnel::instance', 'pki', $name, { 'default_value' => simplib::lookup('simp_options::pki', { 'default_value' => false }) }),
  Stdlib::Absolutepath                        $app_pki_dir             = simplib::dlookup('stunnel::instance', 'app_pki_dir', $name, { 'default_value' => "/etc/pki/simp_apps/stunnel_${name}/x509" }),
  String                                      $app_pki_external_source = simplib::dlookup('stunnel::instance', 'app_pki_external_source', $name, { 'default_value' => simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }) }),
  Stdlib::Absolutepath                        $app_pki_key             = simplib::dlookup('stunnel::instance', 'app_pki_key', $name, { 'default_value' => "${app_pki_dir}/private/${facts['fqdn']}.pem" }),
  Stdlib::Absolutepath                        $app_pki_cert            = simplib::dlookup('stunnel::instance', 'app_pki_cert', $name, { 'default_value' => "${app_pki_dir}/public/${facts['fqdn']}.pub" }),
  Stdlib::Absolutepath                        $app_pki_ca_dir          = simplib::dlookup('stunnel::instance', 'app_pki_ca_dir', $name, { 'default_value' => "${app_pki_dir}/cacerts" }),
  Stdlib::Absolutepath                        $app_pki_cacert          = simplib::dlookup('stunnel::instance', 'app_pki_cacert', $name, { 'default_value' => "${app_pki_dir}/cacerts/cacerts.pem" }),
  Stdlib::Absolutepath                        $app_pki_crl             = simplib::dlookup('stunnel::instance', 'app_pki_crl', $name, { 'default_value' => "${app_pki_dir}/crl" }),
  Optional[Stdlib::Absolutepath]              $chroot                  = simplib::dlookup('stunnel::instance', 'chroot', $name, { 'default_value' => undef }),
  Optional[Enum['zlib','rle']]                $compression             = simplib::dlookup('stunnel::instance', 'compression', $name, { 'default_value' => undef }),
  Optional[String]                            $curve                   = simplib::dlookup('stunnel::instance', 'curve', $name, { 'default_value' => undef }),
  Boolean                                     $delay                   = simplib::dlookup('stunnel::instance', 'delay', $name, { 'default_value' => false }),
  Optional[String]                            $egd                     = simplib::dlookup('stunnel::instance', 'egd', $name, { 'default_value' => undef }),
  String                                      $engine                  = simplib::dlookup('stunnel::instance', 'engine', $name, { 'default_value' => 'auto' }),
  Optional[String]                            $engine_ctrl             = simplib::dlookup('stunnel::instance', 'engine_ctrl', $name, { 'default_value' => undef }),
  Optional[Integer]                           $engine_num              = simplib::dlookup('stunnel::instance', 'engine_num', $name, { 'default_value' => undef }),
  Optional[String]                            $exec                    = simplib::dlookup('stunnel::instance', 'exec', $name, { 'default_value' => undef }),
  Array[String]                               $execargs                = simplib::dlookup('stunnel::instance', 'execargs', $name, { 'default_value' => [] }),
  Enum['rr','prio']                           $failover                = simplib::dlookup('stunnel::instance', 'failover', $name, { 'default_value' => 'rr' }),
  Boolean                                     $fips                    = simplib::dlookup('stunnel::instance', 'fips', $name, { 'default_value' => simplib::lookup('simp_options::fips', { 'default_value' => pick($facts['fips_enabled'], false) }) }),
  Optional[String]                            $local                   = simplib::dlookup('stunnel::instance', 'local', $name, { 'default_value' => undef }),
  Optional[Simplib::URI]                      $ocsp                    = simplib::dlookup('stunnel::instance', 'ocsp', $name, { 'default_value' => undef }),
  Stunnel::OcspFlags                          $ocsp_flags              = simplib::dlookup('stunnel::instance', 'ocsp_flags', $name, { 'default_value' => [] }),
  Array[String]                               $openssl_cipher_suite    = simplib::dlookup('stunnel::instance', 'openssl_cipher_suite', $name, { 'default_value' => ['HIGH','-SSLv2'] }),
  Array[String]                               $options                 = simplib::dlookup('stunnel::instance', 'options', $name, { 'default_value' => [] }),
  Optional[Stdlib::Absolutepath]              $output                  = simplib::dlookup('stunnel::instance', 'output', $name, { 'default_value' => undef }),
  Optional[Stdlib::Absolutepath]              $pid                     = simplib::dlookup('stunnel::instance', 'pid', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol                = simplib::dlookup('stunnel::instance', 'protocol', $name, { 'default_value' => undef }),
  Optional[Enum['basic','NTLM']]              $protocol_authentication = simplib::dlookup('stunnel::instance', 'protocol_authentication', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_host           = simplib::dlookup('stunnel::instance', 'protocol_host', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_username       = simplib::dlookup('stunnel::instance', 'protocol_username', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_password       = simplib::dlookup('stunnel::instance', 'protocol_password', $name, { 'default_value' => undef }),
  Boolean                                     $pty                     = simplib::dlookup('stunnel::instance', 'pty', $name, { 'default_value' => false }),
  Boolean                                     $renegotiation           = simplib::dlookup('stunnel::instance', 'renegotiation', $name, { 'default_value' => true }),
  Boolean                                     $reset                   = simplib::dlookup('stunnel::instance', 'reset', $name, { 'default_value' => true }),
  Boolean                                     $retry                   = simplib::dlookup('stunnel::instance', 'retry', $name, { 'default_value' => false }),
  Optional[Integer]                           $rnd_bytes               = simplib::dlookup('stunnel::instance', 'rnd_bytes', $name, { 'default_value' => undef }),
  Optional[Stdlib::Absolutepath]              $rnd_file                = simplib::dlookup('stunnel::instance', 'rnd_file', $name, { 'default_value' => undef }),
  Boolean                                     $rnd_overwrite           = simplib::dlookup('stunnel::instance', 'rnd_overwrite', $name, { 'default_value' => false }),
  Optional[Integer]                           $session_cache_size      = simplib::dlookup('stunnel::instance', 'session_cache_size', $name, { 'default_value' => undef }),
  Optional[Integer]                           $session_cache_timeout   = simplib::dlookup('stunnel::instance', 'session_cache_timeout', $name, { 'default_value' => undef }),
  String                                      $setuid                  = simplib::dlookup('stunnel::instance', 'setuid', $name, { 'default_value' => 'stunnel' }),
  String                                      $setgid                  = simplib::dlookup('stunnel::instance', 'setgid', $name, { 'default_value' => 'stunnel' }),
  Integer                                     $uid                     = simplib::dlookup('stunnel::instance', 'uid', $name, { 'default_value' => 600 }),
  Integer                                     $gid                     = simplib::dlookup('stunnel::instance', 'gid', $name, { 'default_value' =>                                                                                                        $uid }),
  Optional[String]                            $sni                     = simplib::dlookup('stunnel::instance', 'sni', $name, { 'default_value' => undef }),
  Array[String]                               $socket_options          = simplib::dlookup('stunnel::instance', 'socket_options', $name, { 'default_value' => [] }),
  Optional[String]                            $ssl_version             = simplib::dlookup('stunnel::instance', 'ssl_version', $name, { 'default_value' => undef }),
  Optional[Integer]                           $stack                   = simplib::dlookup('stunnel::instance', 'stack', $name, { 'default_value' => undef }),
  String                                      $stunnel_debug           = simplib::dlookup('stunnel::instance', 'stunnel_debug', $name, { 'default_value' => 'err' }),
  Boolean                                     $syslog                  = simplib::dlookup('stunnel::instance', 'syslog', $name, { 'default_value' => simplib::lookup('simp_options::syslog', { 'default_value' => false }) }),
  Optional[Integer]                           $timeout_busy            = simplib::dlookup('stunnel::instance', 'timeout_busy', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_close           = simplib::dlookup('stunnel::instance', 'timeout_close', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_connect         = simplib::dlookup('stunnel::instance', 'timeout_connect', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_idle            = simplib::dlookup('stunnel::instance', 'timeout_idle', $name, { 'default_value' => undef }),
  Integer                                     $verify                  = simplib::dlookup('stunnel::instance', 'verify', $name, { 'default_value' => 2 }),
  Optional[Array[String]]                     $systemd_wantedby        = simplib::dlookup('stunnel::instance', 'systemd_wantedby', $name, { 'default_value' => undef }),
  Optional[Array[String]]                     $systemd_requiredby      = simplib::dlookup('stunnel::instance', 'systemd_requiredby', $name, { 'default_value' => undef }),
){
  $_safe_name = regsubst($name, '(/|\s)', '__')
  $_dport = split(to_string($accept),':')[-1]

  $_on_systemd = 'systemd' in $facts['init_systems']

  stunnel::instance::reserve_port { $_dport: }

  if $haveged { include '::haveged' }

  include '::stunnel'

  # Validation for RHEL6/7 Options. Defaulting to 7.
  if ($facts['os']['name'] in ['Red Hat','CentOS']) and ($facts['os']['release']['major'] < '7') {
    if $fips {
      if $ssl_version { validate_array_member($ssl_version,['TLSv1']) }
    }
    else {
      if $ssl_version { validate_array_member($ssl_version,['all','SSLv2','SSLv3','TLSv1']) }
    }
    if $protocol {
      validate_array_member($protocol,['cifs','connect','imap','nntp','pgsql','pop3','smtp'])
    }
  }
  else {
    if $fips {
      if $ssl_version { validate_array_member($ssl_version,['TLSv1','TLSv1.1','TLSv1.2']) }
    }
    else {
      if $ssl_version {
        validate_array_member($ssl_version,['all','SSLv2','SSLv3','TLSv1','TLSv1.1','TLSv1.2'])
      }
    }
    if $protocol {
      validate_array_member($protocol,['cifs','connect','imap','nntp','pgsql','pop3','proxy','smtp'])
    }
  }

  ensure_resource('stunnel::account', $setuid,
    {
      'groupname' => $setgid,
      'uid'       => $uid,
      'gid'       => $gid
    }
  )

  if $chroot {
    $_chroot = $chroot
  }
  elsif $facts['selinux_current_mode'] and $facts['selinux_current_mode'] == 'disabled' {
    $_chroot = "/var/stunnel_${_safe_name}"
  }
  else {
    $_chroot = undef
  }

  if !$pid and $_on_systemd {
    $_foreground = true
    $_pid        = $pid
  } else {
    $_foreground = undef
    $_pid        = "/var/run/stunnel/stunnel_managed_by_puppet_${_safe_name}.pid"
  }

  file { "/etc/stunnel/stunnel_managed_by_puppet_${_safe_name}.conf":
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('stunnel/instance_conf.erb'),
    require => File['/etc/stunnel']
  }

  if $pki {
    pki::copy { "stunnel_${name}":
      source => $app_pki_external_source,
      pki    => $pki,
      notify => Service["stunnel_managed_by_puppet_${_safe_name}"]
    }
  }

  if $_chroot {
    if $_chroot in ['/',''] {
      fail("stunnel: \$chroot should not be root ('/')")
    }
    if $_chroot =~ /^\/var\/run/ {
      fail("stunnel: \$chroot cannot be under /var/run")
    }

    if $_pid {
      $_stunnel_pid_dirname = dirname("${_chroot}/${_pid}")

      $_stunnel_piddir = File[$_stunnel_pid_dirname]
      $_stunnel_chroot_seltype = 'stunnel_var_run_t'

      exec { "mkdir -p ${_stunnel_pid_dirname}":
        path    => ['/bin','/usr/bin'],
        creates => $_chroot,
        before  => File[$_chroot]
      }

      unless $_on_systemd {
        ensure_resource('file', $_stunnel_pid_dirname,
          {
            'ensure'  => 'directory',
            'owner'   => $setuid,
            'group'   => $setgid,
            'mode'    => '0644',
            'seluser' => 'system_u',
            'selrole' => 'object_r',
            'seltype' => $_stunnel_chroot_seltype
          }
        )
      }
    }
    else {
      $_stunnel_piddir = undef
      $_stunnel_chroot_seltype = undef

      exec { "mkdir -p ${_chroot}":
        path    => ['/bin','/usr/bin'],
        creates => $_chroot,
        before  => File[$_chroot]
      }
    }

    file { $_chroot:
      ensure  => 'directory',
      owner   => 'root',
      group   => $setgid,
      mode    => '0640',
      seltype => $_stunnel_chroot_seltype
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
      owner  => 'root',
      group  => 'root',
      mode   => '0644'
    }

    file { "${_chroot}/etc/pki":
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0640'
    }

    $_require_pki =  $pki ? { true => Pki::Copy["stunnel_${name}"], default => undef }

    file { "${_chroot}/etc/pki/cacerts":
      source  => "file://${app_pki_dir}/cacerts",
      group   => $setgid,
      mode    => '0640',
      recurse => true,
      require => $_require_pki
    }
  }
  else {
    if $_pid {
      $_stunnel_piddir = File[dirname($_pid)]

      unless $_on_systemd {
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
    } else {
      $_stunnel_piddir = undef
    }
  }

  # The rules are pulled together from the accept_* and connect_*
  # variables.
  #
  # This is only enabled if the system is a server.
  if $firewall and !$client {
    include '::iptables'

    iptables::listen::tcp_stateful { "allow_stunnel_${_safe_name}":
      trusted_nets => $trusted_nets,
      dports       => [to_integer($_dport)]
    }
  }

  if !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${_safe_name}":
      pattern => nets2ddq($trusted_nets),
      svc     => $_safe_name
    }
  }

  if $_on_systemd {
    $_service_file = "/etc/systemd/system/stunnel_managed_by_puppet_${_safe_name}.service"
    file { $_service_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('stunnel/instance_systemd.erb'),
    }
  }
  elsif 'sysv' in $facts['init_systems'] {
    $_service_file = "/etc/rc.d/init.d/stunnel_managed_by_puppet_${_safe_name}"
    file { $_service_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => template('stunnel/instance_init.erb')
    }
  }
  else {
    fail("Init systems ${$facts['init_systems']} not supported. Only 'systemd' and 'sysv' supported.")
  }

  service { "stunnel_managed_by_puppet_${_safe_name}":
    ensure  => 'running',
    enable  => true,
    require => [
      File[$_service_file],
      File["/etc/stunnel/stunnel_managed_by_puppet_${_safe_name}.conf"]
    ] + $_stunnel_piddir
  }
}
