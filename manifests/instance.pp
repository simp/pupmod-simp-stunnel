# Set up a stunnel connection with a unique configuration and service
#
# @example Add an Rsync listener
#  stunnel::instance {'rsync':
#    accept  => 873,
#    connect => ['1.2.3.4:8730']
#  }
#
# - Creates /etc/stunnel/stunnel_rsync.conf
# - Spawns service 'stunnel_rsync' from stunnel_rsync.conf
#
# @param name [String]
#   The name of the stunnel process. For example, a name of 'nfs'
#   would result in a service stunnel_nfs
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
#   it will default to `/var/stunnel_${name}`.
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

  Simplib::Netlist                            $trusted_nets            = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] }),
  Boolean                                     $firewall                = simplib::lookup('simp_options::firewall', { 'default_value' => false }),
  Boolean                                     $haveged                 = simplib::lookup('simp_options::haveged', { 'default_value' => true }),
  Boolean                                     $tcpwrappers             = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }),

  Variant[Enum['simp'],Boolean]               $pki                     = simplib::lookup('simp_options::pki', { 'default_value' => false }),
  Stdlib::Absolutepath                        $app_pki_dir             = "/etc/pki/simp_apps/stunnel_${name}/x509",
  Stdlib::Absolutepath                        $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath                        $app_pki_key             = "${app_pki_dir}/private/${facts['fqdn']}.pem",
  Stdlib::Absolutepath                        $app_pki_cert            = "${app_pki_dir}/public/${facts['fqdn']}.pub",
  Stdlib::Absolutepath                        $app_pki_ca_dir          = "${app_pki_dir}/cacerts",
  Stdlib::Absolutepath                        $app_pki_cacert          = "${app_pki_dir}/cacerts/cacerts.pem",
  Stdlib::Absolutepath                        $app_pki_crl             = "${app_pki_dir}/crl",
  Optional[Stdlib::Absolutepath]              $chroot                  = undef,
  Boolean                                     $client                  = true,
  Optional[Enum['zlib','rle']]                $compression             = undef,
  Optional[String]                            $curve                   = undef,
  Boolean                                     $delay                   = false,
  Optional[String]                            $egd                     = undef,
  String                                      $engine                  = 'auto',
  Optional[String]                            $engine_ctrl             = undef,
  Optional[Integer]                           $engine_num              = undef,
  Optional[String]                            $exec                    = undef,
  Array[String]                               $execargs                = [],
  Enum['rr','prio']                           $failover                = 'rr',
  Boolean                                     $fips                    = simplib::lookup('simp_options::fips', { 'default_value' => pick($facts['fips_enabled'], false) }),
  Optional[String]                            $local                   = undef,
  Optional[Simplib::URI]                      $ocsp                    = undef,
  Stunnel::OcspFlags                          $ocsp_flags              = [],
  Array[String]                               $openssl_cipher_suite    = ['HIGH','-SSLv2'],
  Array[String]                               $options                 = [],
  Optional[Stdlib::Absolutepath]              $output                  = undef,
  Optional[Stdlib::Absolutepath]              $pid                     = undef,
  Optional[String]                            $protocol                = undef,
  Optional[Enum['basic','NTLM']]              $protocol_authentication = undef,
  Optional[String]                            $protocol_host           = undef,
  Optional[String]                            $protocol_username       = undef,
  Optional[String]                            $protocol_password       = undef,
  Boolean                                     $pty                     = false,
  Boolean                                     $renegotiation           = true,
  Boolean                                     $reset                   = true,
  Boolean                                     $retry                   = false,
  Optional[Integer]                           $rnd_bytes               = undef,
  Optional[Stdlib::Absolutepath]              $rnd_file                = undef,
  Boolean                                     $rnd_overwrite           = false,
  Optional[Integer]                           $session_cache_size      = undef,
  Optional[Integer]                           $session_cache_timeout   = undef,
  String                                      $setuid                  = 'stunnel',
  String                                      $setgid                  = 'stunnel',
  Integer                                     $uid                     = 600,
  Integer                                     $gid                     = $uid,
  Optional[String]                            $sni                     = undef,
  Array[String]                               $socket_options          = [],
  Optional[String]                            $ssl_version             = undef,
  Optional[Integer]                           $stack                   = undef,
  String                                      $stunnel_debug           = 'err',
  Boolean                                     $syslog                  = simplib::lookup('simp_options::syslog', { 'default_value' => false }),
  Optional[Integer]                           $timeout_busy            = undef,
  Optional[Integer]                           $timeout_close           = undef,
  Optional[Integer]                           $timeout_connect         = undef,
  Optional[Integer]                           $timeout_idle            = undef,
  Integer                                     $verify                  = 2
){

  include '::stunnel::install'

  if $haveged { include '::haveged' }

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

  ensure_resource('stunnel::account', $setuid, { 'groupname' => $setgid, 'uid' => $uid, 'gid' => $gid })

  $_safe_name = regsubst($name, '(/|\s)', '__')

  if $chroot {
    $_chroot = $chroot
  }
  elsif $facts['selinux_current_mode'] and $facts['selinux_current_mode'] == 'disabled' {
    $_chroot = "/var/stunnel_${_safe_name}"
  }
  else {
    $_chroot = undef
  }

  if $pid =~ Undef {
    $on_systemd = 'systemd' in $facts['init_systems']
    $_pid = $on_systemd ? {
      true    => $pid,
      default => "/var/run/stunnel/stunnel_${_safe_name}.pid"
    }
  } else {
    $_pid = $pid
  }

  if 'systemd' in $facts['init_systems'] {
    $_foreground = true
  } else {
    $_foreground = false
  }

  file { "/etc/stunnel/stunnel_${_safe_name}.conf":
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('stunnel/instance_conf.erb'),
    require => File['/etc/stunnel']
  }

  if $pki {
    pki::copy { "stunnel_${_safe_name}":
      source => $app_pki_external_source,
      pki    => $pki,
      notify => Service["stunnel_${_safe_name}"]
    }
  }

  if $_chroot !~ Undef {
    $_stunnel_piddir = File[dirname("${_chroot}${_pid}")]

    file { $_chroot:
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0770',
    }

    # The following two entries are required to be able to properly resolve
    # hosts using the _chroot directory.
    file { "${_chroot}/etc":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
    file { "${_chroot}/etc/resolv.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/resolv.conf',
    }

    file { "${_chroot}/etc/nsswitch.conf":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/nsswitch.conf',
    }

    file { "${_chroot}/etc/hosts":
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'file:///etc/hosts',
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

    # The selinux context settings are ignored if SELinux is disabled
    ensure_resource('file', dirname("${_chroot}${_pid}"),
      {
        'ensure'  => 'directory',
        'owner'   => $setuid,
        'group'   => $setgid,
        'mode'    => '0644',
        'seluser' => 'system_u',
        'selrole' => 'object_r',
        'seltype' => 'stunnel_var_run_t'
      }
    )

    file { "${_chroot}/etc/pki":
      ensure => 'directory',
      owner  => 'root',
      group  => $setgid,
      mode   => '0640'
    }

    $_require_pki =  $pki ? { true => Pki::Copy["stunnel_${_safe_name}"], default =>  undef }

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

    $_dport = [to_integer(split(to_string($accept),':')[-1])]

    iptables::listen::tcp_stateful { "allow_stunnel_${_safe_name}":
      trusted_nets => $trusted_nets,
      dports       => $_dport
    }
  }

  if !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${_safe_name}":
      pattern => nets2ddq($trusted_nets)
    }
  }

  $_se_enabled = $facts['selinux_enforced']
  if 'upstart' in $facts['init_systems'] {
    $_service_file = "/etc/rc.d/init.d/stunnel_${_safe_name}"
    file { $_service_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => template('stunnel/instance_init.erb')
    }
  }
  elsif 'systemd' in $facts['init_systems'] {
    $_service_file = "/etc/systemd/system/stunnel_${_safe_name}.service"
    file { $_service_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('stunnel/instance_systemd.erb'),
    }
  }
  else {
    fail("Init systems ${$facts['init_systems']} not supported. Only systemd, upstart supported.")
  }


  service { "stunnel_${_safe_name}":
    ensure     => 'running',
    enable     => true,
    require    => [
      File[$_service_file],
      File["/etc/stunnel/stunnel_${_safe_name}.conf"]
    ] + $_stunnel_piddir
  }
}
