# Set up a stunnel connection with a unique configuration and service
#
# @example Add an Rsync listener
#  stunnel::standalone ('rsync':
#    accept  => '873',
#    connect =>  ['1.2.3.4:8730']
#  }
#
# - Creates /etc/stunnel/stunnel_rsync.conf
# - Spawns service 'stunnel_rsync' from stunnel_rsync.conf
#
# @param name [String]
#   The name used to separate stunnel processes. For example, a name
#   of 'nfs' would result in a service stunnel_nfs
#
# @param chroot
#   The location of the chroot jail
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
# @param fips
#   Set the ``fips`` global option
#
#   * We don't enable FIPS mode by default since we want to be able to use
#     TLS1.2
#
#   * **NOTE:** This has no effect on EL < 7 due to stunnel not accepting the
#     fips option in that version of stunnel
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
# @param client
#   Indicates that this connection is a client connection
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
#
# @param trusted_nets
#   Set this if you don't want to allow all IP addresses to access this
#   connection
#
#   * This only makes sense for servers
#
# @param firewall
#   Include the SIMP ``iptables`` module to manage the firewall
#
# @param tcpwrappers
#   Include the SIMP ``tcpwrappers`` module to manage tcpwrappers
#
# All other configuration options can be found in the stunnel man pages
# @see stunnel.conf(5)
# @see stunnel.conf(8)
#
# @author Nick Markowski <nmarkowski@keywcorp.com>
#
define stunnel::standalone(
  Simplib::Netlist                            $trusted_nets            = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] }),
  Boolean                                     $firewall                = simplib::lookup('simp_options::firewall', { 'default_value'     => false }),
  Boolean                                     $tcpwrappers             = simplib::lookup('simp_options::tcpwrappers', { 'default_value'  => false }),


  Variant[Enum['simp'],Boolean]               $pki                     = simplib::lookup('simp_options::pki', { 'default_value'          =>  false }),
  Stdlib::Absolutepath                        $app_pki_dir             = "/etc/pki/simp_apps/stunnel_${name}/x509",
  Stdlib::Absolutepath                        $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value'  => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath                        $app_pki_key             = "${app_pki_dir}/private/${facts['fqdn']}.pem",
  Stdlib::Absolutepath                        $app_pki_cert            = "${app_pki_dir}/public/${facts['fqdn']}.pub",
  Stdlib::Absolutepath                        $app_pki_ca_dir          = "${app_pki_dir}/cacerts",
  Stdlib::Absolutepath                        $app_pki_cacert          = "${app_pki_dir}/cacerts/cacerts.pem",
  Stdlib::Absolutepath                        $app_pki_crl             = "${app_pki_dir}/crl",
  Variant[Simplib::Port, Simplib::Host::Port] $accept,
  Optional[Stdlib::Absolutepath]              $chroot                  = undef,
  Boolean                                     $client                  = true,
  Optional[Enum['zlib','rle']]                $compression             = undef,
  Stunnel::Connect                            $connect,
  Optional[String]                            $curve                   = undef,
  Boolean                                     $delay                   = false,
  Optional[String]                            $egd                     = undef,
  String                                      $engine                  = 'auto',
  Optional[String]                            $engine_ctrl             = undef,
  Optional[Integer]                           $engine_num              = undef,
  Optional[String]                            $exec                    = undef,
  Array[String]                               $execargs                = [],
  Enum['rr','prio']                           $failover                = 'rr',
  Boolean                                     $fips                    = simplib::lookup('simp_options::fips', { 'default_value'         => false }),
  Optional[String]                            $local                   = undef,
  Optional[Simplib::URI]                      $ocsp                    = undef,
  Stunnel::OcspFlags                          $ocsp_flags              = [],
  Array[String]                               $openssl_cipher_suite    = ['HIGH','-SSLv2'],
  Array[String]                               $options                 = [],
  Optional[Stdlib::Absolutepath]              $output                  = undef,
  Stdlib::Absolutepath                        $pid                     = "/var/run/stunnel/stunnel_${name}.pid",
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
  Optional[String]                            $sni                     = undef,
  Array[String]                               $socket_options          = [],
  Optional[String]                            $ssl_version             = undef,
  Optional[Integer]                           $stack                   = undef,
  String                                      $stunnel_debug           = 'err',
  Boolean                                     $syslog                  = simplib::lookup('simp_options::syslog', { 'default_value'       => false }),
  Optional[Integer]                           $timeout_busy            = undef,
  Optional[Integer]                           $timeout_close           = undef,
  Optional[Integer]                           $timeout_connect         = undef,
  Optional[Integer]                           $timeout_idle            = undef,
  Integer                                     $verify                  = 2
){

  include '::stunnel::install'

  # Validation for RHEL6/7 Options. Defaulting to 7.
  if ($facts['os']['name'] in ['Red Hat','CentOS']) and ($facts['os']['release']['major'] < '7') {
    if $::stunnel::fips {
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
    if $::stunnel::fips {
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

  if $chroot {
    $_chroot = $chroot
  }
  elsif $facts['selinux_current_mode'] and $facts['selinux_current_mode'] == 'disabled' {
    $_chroot = "/var/stunnel_${name}"
  }
  else {
    $_chroot = undef
  }

  file { "/etc/stunnel/stunnel_${name}.conf":
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => template('stunnel/standalone_conf.erb'),
    require => File['/etc/stunnel']
  }

  if $pki {
    pki::copy { "stunnel_${name}":
      source => $app_pki_external_source,
      pki    => $pki,
      notify =>  Service["stunnel_${name}"]
    }
  }

  # NOTE: The pidfile directory is ensured by the service file(s)
  if $_chroot {
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
  }

  # The rules are pulled together from the accept_* and connect_*
  # variables.
  #
  # This is only enabled if the system is a server.
  if $firewall and !$client {
    include '::iptables'

    $_dport = [to_integer(split(to_string($accept),':')[-1])]

    iptables::listen::tcp_stateful { "allow_stunnel_${name}":
      trusted_nets => $trusted_nets,
      dports       => $_dport
    }
  }

  if !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${name}":
      pattern => nets2ddq($trusted_nets)
    }
  }

  if ($facts['os']['name'] in ['RedHat','CentOS']) {
    if ($facts['os']['release']['major'] < '7') {
      $_service_file = "/etc/rc.d/init.d/stunnel_${name}"
      file { $_service_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0750',
        content => template('stunnel/standalone_init.erb'),
        tag     => 'firstrun',
      }
    }
    else {
      $_service_file = "/etc/systemd/system/stunnel_${name}.service"
      file { $_service_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0750',
        content => template('stunnel/standalone_systemd.erb'),
      }
    }
  }

  service { "stunnel_${name}":
    ensure     => 'running',
    enable     => true,
    hasrestart => true,
    hasstatus  => true,
    require    => [
      File[$_service_file],
      File["/etc/stunnel/stunnel_${name}.conf"]
    ],
  }
}
