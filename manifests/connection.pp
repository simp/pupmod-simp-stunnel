# Set up a stunnel connection for the service ``$name``
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
# ``rsync``: ``Stunnel::Connection[rsync]::ssl_version: 'TLSv1.2'``
#
# @example Add an Rsync listener
#  stunnel::connection ('rsync':
#    accept       => '873',
#    connect_addr => ['1.2.3.4:8730']
#  }
#
# @see stunnel.conf(5)
# @see stunnel.conf(8)
#
# @param name [String]
#   The service name
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
# @param failover
#   The failover strategy for multiple connect targets
#
# @param sni
#   See the 'sni' option documentation in ``stunnel(8)``
#
#   This option is only valid on EL 7+
#
# @param app_pki_key
#   Path and name of the private SSL key file
#
# @param app_pki_cert
#   Path and name of the public SSL certificate
#
# @param app_pki_cacert
#   Path to the OpenSSL compatible CA certificates
#
#   * **NOTE:** this path is relative to the chroot path if set and is expected
#   to be a directory
#
# @param app_pki_crl
#   Path to the OpenSSL compatible CRL directory
#
# @param openssl_cipher_suite
#   OpenSSL compatible array of ciphers to allow on the system
#
# @param curve
#   The ECDH curve name to use. To get a list of supported curves use:
#   ``openssl ecparam -list_curves`` on your *client*
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
# @param verify
#   Level of mutual authentication to perform
#
#   * RHEL 6 Options:
#       * level 1 - verify peer certificate if present
#       * level 2 - verify peer certificate
#       * level 3 - verify peer with locally installed certificate
#       * default - no verify
#
#   * RHEL 7 Options:
#       * level 0 - Request and ignore peer certificate.
#       * level 1 - Verify peer certificate if present.
#       * level 2 - Verify peer certificate.
#       * level 3 - Verify peer with locally installed certificate.
#       * level 4 - Ignore CA chain and only verify peer certificate.
#       * default - No verify
#
# @param ocsp
#   The OCSP responder to use for certificate validation
#
# @param ocsp_flags
#   The OCSP server flags
#
# @param local
#   The outgoing IP to which to bind
#
#   By default, stunnel binds to all interfaces
#
# @param protocol
#   The application protocol to negotiate SSL.
#
#   * RHEL/CentOS 6:  [cifs|connect|imap|nntp|pgsql|pop3|smtp]
#   * RHEL/CentOS 7+: [cifs|connect|imap|nntp|pgsql|pop3|proxy|smtp]
#
# @param protocol_authentication
#   Authentication type for protocol negotiations
#
# @param protocol_host
#   The destination address for protocol negotiations
#
# @param protocol_password
#   The password for protocol negotiations
#
# @param protocol_username
#   The username for protocol negotiations
#
# @param delay
#   Delay DNS lookup for ``connect`` option
#
# @param engine_num
#   The engine number from which to read the private key
#
# @param pty
#   Reserve and assign a pty to a program that is run by stunnel inetd-style
#   using the ``exec`` option
#
# @param renegotiation
#   Support SSL renegotiation
#
# @param reset
#   Attempt to use TCP ``RST`` flag to indicate an error
#
# @param retry
#   Reconnect a ``connect+exec`` session after it has been disconnected
#
# @param session_cache_size
#   The maximum number of internal session cache entries
#
#   * Set to 0 for ``unlimited`` (**not advised**)
#
#   * This option is only valid on EL 7+
#
# @param session_cache_timeout
#   The number of seconds to keep cached SSL sessions
#
#   * Corresponds to the ``session_timeout`` variable in EL 6
#
# @param stack
#   Thread stack size in **bytes**
#
# @param timeout_busy
#   Time to wait for expected data in **seconds**
#
# @param timeout_close
#   Time to wait for close notify in **seconds**
#
# @param timeout_connect
#   Time to wait for a remote host connection in **seconds**
#
# @param timeout_idle
#   Time to keep an idle connection in **seconds**
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
# @param exec
# @param execargs
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
define stunnel::connection (
  Stunnel::Connect                            $connect,
  Variant[Simplib::Port, Simplib::Host::Port] $accept,
  Boolean                                     $client                  = true,
  Enum['rr','prio']                           $failover                = simplib::dlookup('stunnel::connection', 'failover', $name, { 'default_value' => 'rr' }),
  Optional[String]                            $sni                     = simplib::dlookup('stunnel::connection', 'sni', $name, { 'default_value' => undef }),
  Optional[Stdlib::Absolutepath]              $app_pki_key             = simplib::dlookup('stunnel::connection', 'app_pki_key', $name, { 'default_value' => undef }),
  Optional[Stdlib::Absolutepath]              $app_pki_cert            = simplib::dlookup('stunnel::connection', 'app_pki_cert', $name, { 'default_value' => undef }),
  Stdlib::Absolutepath                        $app_pki_cacert          = simplib::dlookup('stunnel::connection', 'app_pki_cacert', $name, { 'default_value' => '/etc/pki/simp_apps/stunnel/x509/cacerts/cacerts.pem' }),
  Stdlib::Absolutepath                        $app_pki_crl             = simplib::dlookup('stunnel::connection', 'app_pki_crl', $name, { 'default_value' => '/etc/pki/simp_apps/stunnel/x509/crl' }),
  Array[String]                               $openssl_cipher_suite    = simplib::dlookup('stunnel::connection', 'openssl_cipher_suite', $name, { 'default_value' => ['HIGH','-SSLv2'] }),
  Optional[String]                            $curve                   = simplib::dlookup('stunnel::connection', 'curve', $name, { 'default_value' => undef }),
  Optional[String]                            $ssl_version             = simplib::dlookup('stunnel::connection', 'ssl_version', $name, { 'default_value' => undef }),
  Array[String]                               $options                 = simplib::dlookup('stunnel::connection', 'options', $name, { 'default_value' => [] }),
  Integer                                     $verify                  = simplib::dlookup('stunnel::connection', 'verify', $name, { 'default_value' => 2 }),
  Optional[Simplib::URI]                      $ocsp                    = simplib::dlookup('stunnel::connection', 'ocsp', $name, { 'default_value' => undef }),
  Stunnel::OcspFlags                          $ocsp_flags              = simplib::dlookup('stunnel::connection', 'ocsp_flags', $name, { 'default_value' => [] }),
  Optional[String]                            $local                   = simplib::dlookup('stunnel::connection', 'local', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol                = simplib::dlookup('stunnel::connection', 'protocol', $name, { 'default_value' => undef }),
  Optional[Enum['basic','NTLM']]              $protocol_authentication = simplib::dlookup('stunnel::connection', 'protocol_authentication', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_host           = simplib::dlookup('stunnel::connection', 'protocol_host', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_username       = simplib::dlookup('stunnel::connection', 'protocol_username', $name, { 'default_value' => undef }),
  Optional[String]                            $protocol_password       = simplib::dlookup('stunnel::connection', 'protocol_password', $name, { 'default_value' => undef }),
  Boolean                                     $delay                   = simplib::dlookup('stunnel::connection', 'delay', $name, { 'default_value' => false }),
  Optional[Integer]                           $engine_num              = simplib::dlookup('stunnel::connection', 'engine_num', $name, { 'default_value' => undef }),
  Optional[String]                            $exec                    = simplib::dlookup('stunnel::connection', 'exec', $name, { 'default_value' => undef }),
  Array[String]                               $execargs                = simplib::dlookup('stunnel::connection', 'execargs', $name, { 'default_value' => [] }),
  Boolean                                     $pty                     = simplib::dlookup('stunnel::connection', 'pty', $name, { 'default_value' => false }),
  Boolean                                     $renegotiation           = simplib::dlookup('stunnel::connection', 'renegotiation', $name, { 'default_value' => true }),
  Boolean                                     $reset                   = simplib::dlookup('stunnel::connection', 'reset', $name, { 'default_value' => true }),
  Boolean                                     $retry                   = simplib::dlookup('stunnel::connection', 'retry', $name, { 'default_value' => false }),
  Optional[Integer]                           $session_cache_size      = simplib::dlookup('stunnel::connection', 'session_cache_size', $name, { 'default_value' => undef }),
  Optional[Integer]                           $session_cache_timeout   = simplib::dlookup('stunnel::connection', 'session_cache_timeout', $name, { 'default_value' => undef }),
  Optional[Integer]                           $stack                   = simplib::dlookup('stunnel::connection', 'stack', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_busy            = simplib::dlookup('stunnel::connection', 'timeout_busy', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_close           = simplib::dlookup('stunnel::connection', 'timeout_close', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_connect         = simplib::dlookup('stunnel::connection', 'timeout_connect', $name, { 'default_value' => undef }),
  Optional[Integer]                           $timeout_idle            = simplib::dlookup('stunnel::connection', 'timeout_idle', $name, { 'default_value' => undef }),
  Simplib::Netlist                            $trusted_nets            = pick(simplib::dlookup('stunnel::connection', 'trusted_nets', $name, {'default_value' => undef }), simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] })),
  Boolean                                     $firewall                = pick(simplib::dlookup('stunnel::connection', 'firewall', $name, {'default_value' => undef }), simplib::lookup('simp_options::firewall', { 'default_value' => false })),
  Boolean                                     $tcpwrappers             = pick(simplib::dlookup('stunnel::connection', 'tcpwrappers', $name, {'default_value' => undef }), simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false }))
) {

  $_dport = split(to_string($accept),':')[-1]

  stunnel::instance::reserve_port { $_dport: }

  include '::stunnel::monolithic'

  # Validation for RHEL6/7 Options. Defaulting to 7.
  if ($facts['os']['name'] in ['RedHat','CentOS','OracleLinux']) and ($facts['os']['release']['major'] < '7') {
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

  if $app_pki_key {
    $_app_pki_key = $app_pki_key
  }
  else {
    $_app_pki_key = $::stunnel::app_pki_key
  }
  if $app_pki_cert {
    $_app_pki_cert = $app_pki_cert
  }
  else {
    $_app_pki_cert = $::stunnel::app_pki_cert
  }
  if $app_pki_cacert {
    $_app_pki_cacert = $app_pki_cacert
  }
  else {
    $_app_pki_cacert = $::stunnel::app_pki_cacert
  }
  if $app_pki_crl {
    $_app_pki_crl = $app_pki_crl
  }
  else {
    $_app_pki_crl = $::stunnel::app_pki_crl
  }

  concat::fragment { "stunnel_connection_${name}":
    target  => '/etc/stunnel/stunnel.conf',
    content => template('stunnel/connection_conf.erb')
  }

  # The rules are pulled together from the accept_* and connect_*
  # variables.
  #
  # This is only enabled if the system is a server.
  if $firewall and !$client {
    include '::iptables'

    iptables::listen::tcp_stateful { "allow_stunnel_${name}":
      trusted_nets => $trusted_nets,
      dports       => [to_integer($_dport)]
    }
  }

  if !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${name}":
      svc     => $name,
      pattern => nets2ddq($trusted_nets)
    }
  }
}
