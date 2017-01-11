# Set up a stunnel connection for the service ``$name``
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
# @param app_pki_ca_dir
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
#   * This option is only valid on EL 7+
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
#   * This option is only supported on RHEL/CentOS 7+
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
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define stunnel::connection (
  Stunnel::Connect                             $connect,
  Variant[Simplib::Port, Simplib::Host::Port]  $accept,
  Boolean                                      $client                  = true,
  Enum['rr','prio']                            $failover                = 'rr',
  Optional[String]                             $sni                     = undef,
  Optional[Stdlib::Absolutepath]               $app_pki_key             = undef,
  Optional[Stdlib::Absolutepath]               $app_pki_cert            = undef,
  Stdlib::Absolutepath                         $app_pki_ca_dir          = '/etc/pki/simp_apps/stunnel/x509/cacerts',
  Stdlib::Absolutepath                         $app_pki_crl             = '/etc/pki/simp_apps/stunnel/x509/crl',
  Array[String]                                $openssl_cipher_suite    = ['HIGH','-SSLv2'],
  Optional[String]                             $curve                   = undef,
  Optional[String]                             $ssl_version             = undef,
  Array[String]                                $options                 = [],
  Integer                                      $verify                  = 2,
  Optional[Simplib::URI]                       $ocsp                    = undef,
  Stunnel::OcspFlags                           $ocsp_flags              = [],
  Optional[String]                             $local                   = undef,
  Optional[String]                             $protocol                = undef,
  Optional[Enum['basic','NTLM']]               $protocol_authentication = undef,
  Optional[String]                             $protocol_host           = undef,
  Optional[String]                             $protocol_username       = undef,
  Optional[String]                             $protocol_password       = undef,
  Boolean                                      $delay                   = false,
  Optional[Integer]                            $engine_num              = undef,
  Boolean                                      $libwrap                 = false,
  Optional[String]                             $exec                    = undef,
  Array[String]                                $execargs                = [],
  Boolean                                      $pty                     = false,
  Boolean                                      $renegotiation           = true,
  Boolean                                      $reset                   = true,
  Boolean                                      $retry                   = false,
  Optional[Integer]                            $session_cache_size      = undef,
  Optional[Integer]                            $session_cache_timeout   = undef,
  Optional[Integer]                            $stack                   = undef,
  Optional[Integer]                            $timeout_busy            = undef,
  Optional[Integer]                            $timeout_close           = undef,
  Optional[Integer]                            $timeout_connect         = undef,
  Optional[Integer]                            $timeout_idle            = undef,
  Simplib::Netlist                             $trusted_nets            = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] }),
  Boolean                                      $firewall                = simplib::lookup('simp_options::firewall', { 'default_value' => false }),
  Boolean                                      $tcpwrappers             = simplib::lookup('simp_options::tcpwrappers', { 'default_value' => false })
) {
  include '::stunnel'

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
  if $app_pki_ca_dir {
    $_app_pki_ca_dir = $app_pki_ca_dir
  }
  else {
    $_app_pki_ca_dir = $::stunnel::app_pki_ca_dir
  }
  if $app_pki_crl {
    $_app_pki_crl = $app_pki_crl
  }
  else {
    $_app_pki_crl = $::stunnel::app_pki_crl
  }

  concat::fragment { "stunnel_connection_${name}":
    target  => '/etc/stunnel/stunnel.conf',
    content => template("${module_name}/stunnel.erb")
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

  if $libwrap and !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${name}":
      pattern => nets2ddq($trusted_nets)
    }
  }
}
