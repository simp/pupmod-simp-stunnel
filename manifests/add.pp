# == Define: stunnel::add
#
# Set up a stunnel connection for the service $name
#
# == Parameters
#
# [*name*]
#   Type: String
#   Default: Required
#
#   The service name.
#
# [*connect*]
#   Type: Array of [hostname/ip:]port Entries
#   Default: Required
#
#   Address and port to which to forward connections.  For a client,
#   this is the port of the stunnel server.  For the stunnel server,
#   this is the listening port of the tunneled service.  See
#   stunnel.conf(5) for more information.
#
#   Examples:
#     ['my.server:3000','my.server2:3001']
#     ['my.server:3000']
#     ['3000']
#
# [*accept*]
#   Type: String [hostname/ip:]port
#   Default: Required
#
#   Address and port upon which to accept connections.  For a client,
#   this is generally localhost.  For a server, it should be whichever
#   external address is appropriate.  If this is omitted, then
#   connections are accepted on all addresses.
#
#   Examples:
#     '1.2.3.4:3000'
#     '3000'
#
# [*client*]
#   Type: Boolean
#   Default: true
#
#   Whether this instance of stunnel should behave as a client.
#
# [*failover*]
#   Type: [rr|prio]
#   Default: rr
#
#   The failover strategy for multiple connect targets.
#
# [*sni*]
#   Type: [service_name|service_name:server_name_pattern]
#   Default: None
#
#   See the 'sni' option documentation in stunnel(8).
#
#   This option is only valid on RHEL/CentOS 7+.
#
# [*app_pki_key*]
#   Type: Absolute Path
#   Default: ''
#
#   Path and name of the private SSL key file.
#
# [*app_pki_cert*]
#   Type: Absolute Path
#   Default: ''
#
#   Path and name of the public SSL certificate.
#
# [*app_pki_ca_dir*]
#   Type: Absolute Path
#   Default: /var/stunnel_pki/pki/cacerts
#
#   Path to the OpenSSL compatible CA certificates. Note, this path is relative
#   to the chroot path if set and is expected to be a directory.
#
# [*app_pki_crl*]
#   Type: Absolute Path
#   Default: /var/stunnel_pki/pki/crl
#
#   Path to the OpenSSL compatible CRL directory.
#
# [*openssl_cipher_suite*]
#   Type: Array
#   Default: ['HIGH','-SSLv2']
#
#   OpenSSL compatible array of ciphers to allow on the system.
#
# [*curve*]
#   Type: String
#   Default: None
#
#   The ECDH curve name to use. To get a list of supported curves use:
#   openssl ecparam -list_curves on your *client*.
#
#   This option is only valid on RHEL/CentOS 7+.
#
# [*ssl_version*]
#   Type: String
#     Allowed Values (RHEL6): [all|SSLv2|SSLv3|TLSv1]
#     Allowed Values (RHEL7): [all|SSLv2|SSLv3|TLSv1|TLSv1.1|TLSv1.2]
#   Default: None (let the system decide)
#
#   Dictate the SSL version that can be used on the system. You only
#   get one choice from the options listed above.
#
#   This default, combined with the default $ciphers, the system will
#   only negotiate at TLSv1.1 or higher.
#
# [*options*]
#   Type: Array
#   Default: None
#
#   The OpenSSL library options.
#
# [*verify*]
#   Type: Integer (see below)
#   Default: 2
#
#   Level of mutual authentication to perform.
#   See stunnel.conf(5) for more information.
#
#   RHEL 6 Options:
#     level 1 - verify peer certificate if present
#     level 2 - verify peer certificate
#     level 3 - verify peer with locally installed certificate
#     default - no verify
#
#   RHEL 7 Options:
#     level 0 - Request and ignore peer certificate.
#     level 1 - Verify peer certificate if present.
#     level 2 - Verify peer certificate.
#     level 3 - Verify peer with locally installed certificate.
#     level 4 - Ignore CA chain and only verify peer certificate.
#     default - No verify
#
# [*ocsp*]
#   Type: URL
#   Default: None
#
#   The OCSP responder to use for certificate validation.
#
# [*ocsp_flags*]
#   Type: Array of Strings
#   Default: []
#
#   The OCSP server flags.
#   Allowed values:
#     NOCERTS, NOINTERN NOSIGS, NOCHAIN, NOVERIFY, NOEXPLICIT,
#     NOCASIGN, NODELEGATED, NOCHECKS, TRUSTOTHER, RESPID_KEY, NOTIME
#
# [*local*]
#   Type: IP Address
#   Default: None
#
#   The outgoing IP to which to bind. By default, stunnel binds to all
#   interfaces.
#
# [*protocol*]
#   Type: One of:
#     RHEL/CentOS 6:  [cifs|connect|imap|nntp|pgsql|pop3|smtp]
#     RHEL/CentOS 7+: [cifs|connect|imap|nntp|pgsql|pop3|proxy|smtp]
#   Default: None
#
#   The application protocol to negotiate SSL.
#
#   See stunnel(8) for details.
#
# [*protocol_authentication*]
#   Type: [basic|NTLM]
#   Default: None
#
#   Authentication type for protocol negotiations.
#
# [*protocol_host*]
#   Type: Hostname or IP Address
#   Default: None
#
#   The destination address for protocol negotiations.
#
# [*protocol_password*]
#   Type: String
#   Default: None
#
#   The password for protocol negotiations.
#
# [*protocol_username*]
#   Type: String
#   Default: None
#
#   The username for protocol negotiations.
#
# [*delay*]
#   Type: Boolean
#   Default: false
#
#   Delay DNS lookup for 'connect' option
#
# [*engine_num*]
#   Type: Integer
#   Default: None
#
#   The engine number from which to read the private key.
#
#   This option is only supported on RHEL/CentOS 7+.
#
# [*pty*]
#   Type: Boolean
#   Default: false
#
#   Reserve and assign a pty to a program that is run by stunnel inetd-style
#   using the exec option.
#
# [*renegotiation*]
#   Type: Boolean
#   Default: true
#
#   Support SSL renegotiation.
#
# [*reset*]
#   Type: Boolean
#   Default: true
#
#   Attempt to use TCP RST flag to indicate an error.
#
# [*retry*]
#   Type: Boolean
#   Default: false
#
#   Reconnect a connect+exec session after it has been disconnected.
#
# [*session_cache_size*]
#   Type: Integer
#   Default: None
#
#   The maximum number of internal session cache entries. Set to 0 for
#   unlimited (not advised).
#
#   This option is only valid on RHEL/CentOS 7+.
#
# [*session_cache_timeout*]
#   Type: Integer
#   Default: None
#
#   The number of seconds to keep cached SSL sessions.
#
#   Corresponds to the 'session_timeout' variable in RHEL/CentOS 6.
#
# [*stack*]
#   Type: Integer
#   Default: None
#
#   Thread stack size in bytes.
#
# [*timeout_busy*]
#   Type: Integer
#   Default: None
#
#   Time to wait for expected data in seconds.
#
# [*timeout_close*]
#   Type: Integer
#   Default: None
#
#   Time to wait for close notify in seconds.
#
# [*timeout_connect*]
#   Type: Integer
#   Default: None
#
#   Time to wait for a remote host connection in seconds.
#
# [*timeout_idle*]
#   Type: Integer
#   Default: None
#
#   Time to keep an idle connection in seconds.
#
# [*trusted_nets*]
#   Set this if you don't want to allow all IP addresses to access this
#   encrypted channel. This only makes sense for servers.
#
# [*firewall*]
#   Type: Boolean
#   Default: false
#
#   If set to true, include the SIMP IPtables module to manage the firewall.
#
# [*tcpwrappers*]
#   Type: Boolean
#   Default: false
#
#   If set to true, include the SIMP tcpwrappers module to manage tcpwrappers.
#
# == Example
#
#  stunnel::add ('rsync':
#    accept       => '873',
#    connect_addr => ['1.2.3.4:8730']
#  }
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define stunnel::add(
  Array[Pattern[/^(.+:)?\d+$/]]               $connect,
  Pattern[/^(.+:)?\d+$/]                      $accept,
  Boolean                                     $client                  = true,
  Enum['rr','prio']                           $failover                = 'rr',
  Variant[Boolean,Pattern[/^.+(:.+)?$/]]      $sni                     = false,
  Variant[Enum[''],Stdlib::Absolutepath]      $app_pki_key             = '',
  Variant[Enum[''],Stdlib::Absolutepath]      $app_pki_cert            = '',
  Stdlib::Absolutepath                        $app_pki_ca_dir          = '/var/stunnel_pki/pki/cacerts',
  Stdlib::Absolutepath                        $app_pki_crl             = '/var/stunnel_pki/pki/crl',
  Array[String]                               $openssl_cipher_suite    = ['HIGH','-SSLv2'],
  Variant[Boolean, String]                    $curve                   = false,
  Variant[Boolean, String]                    $ssl_version             = false,
  Array[String]                               $options                 = [],
  Stdlib::Compat::Integer                     $verify                  = '2',
  Variant[Boolean, Pattern['^https?://.+$']]  $ocsp                    = false,
  Stunnel::OcspFlags                          $ocsp_flags              = [],
  Variant[Boolean, String]                    $local                   = false,
  Variant[Boolean, String]                    $protocol                = false,
  Variant[Boolean, Enum['basic','NTLM']]      $protocol_authentication = false,
  Variant[Boolean, String]                    $protocol_host           = false,
  Variant[Boolean, String]                    $protocol_username       = false,
  Variant[Boolean, String]                    $protocol_password       = false,
  Boolean                                     $delay                   = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $engine_num              = false,
  Boolean                                     $libwrap                 = false,
  Variant[Boolean, String]                    $exec                    = false,
  Array[String]                               $execargs                = [],
  Boolean                                     $pty                     = false,
  Boolean                                     $renegotiation           = true,
  Boolean                                     $reset                   = true,
  Boolean                                     $retry                   = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $session_cache_size      = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $session_cache_timeout   = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $stack                   = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $timeout_busy            = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $timeout_close           = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $timeout_connect         = false,
  Variant[Boolean, Stdlib::Compat::Integer]   $timeout_idle            = false,
  Array[String]                               $trusted_nets            = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1', '::1'] }),
  Boolean                                     $firewall                = simplib::lookup('simp_options::firewall', { 'default_value'     => false }),
  Boolean                                     $tcpwrappers             = simplib::lookup('simp_options::tcpwrappers', { 'default_value'  => false } )
) {
  include '::stunnel'

  validate_net_list($trusted_nets,'^any$')

  # Validation for RHEL6/7 Options. Defaulting to 7.
  if ($::operatingsystem in ['Red Hat','CentOS']) and ($::operatingsystemmajrelease < '7') {
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

  if empty($app_pki_key) {
    $_app_pki_key = $::stunnel::app_pki_key
  }
  else {
    $_app_pki_key = $app_pki_key
    validate_absolute_path($app_pki_key)
  }
  if empty($app_pki_cert) {
    $_app_pki_cert = $::stunnel::app_pki_cert
  }
  else {
    $_app_pki_cert = $app_pki_cert
    validate_absolute_path($app_pki_cert)
  }
  if empty($app_pki_ca_dir) {
    $_app_pki_ca_dir = $::stunnel::app_pki_ca_dir
  }
  else {
    $_app_pki_ca_dir = $app_pki_ca_dir
    validate_absolute_path($app_pki_ca_dir)
  }
  if empty($app_pki_crl) {
    $_app_pki_crl = $::stunnel::app_pki_crl
  }
  else {
    $_app_pki_crl = $app_pki_crl
    validate_absolute_path($app_pki_crl)
  }


  simpcat_fragment { "stunnel+stunnel_${name}.conf":
    content => template('stunnel/stunnel.erb')
  }

  # The rules are pulled together from the accept_* and connect_*
  # variables.
  #
  # This is only enabled if the system is a server.
  if $firewall and !$client {
    include '::iptables'

    $dport = split($accept,':')

    iptables::add_tcp_stateful_listen { "allow_stunnel_${name}":
      trusted_nets => $trusted_nets,
      dports       => $dport[-1]
    }
  }

  if $libwrap and !$client and $tcpwrappers {
    include '::tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${name}":
      pattern => nets2ddq($trusted_nets)
    }
  }
}
