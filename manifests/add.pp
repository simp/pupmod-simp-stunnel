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
# [*ca_path*]
#   Type: Absolute Path
#   Default: /etc/pki/cacerts
#
#   Path to the OpenSSL compatible CA certificates.
#
# [*crl_path*]
#   Type: Absolute Path
#   Default: /etc/pki/crl
#
#   Path to the OpenSSL compatible CRL directory.
#
# [*ciphers*]
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
# [*client_nets*]
#   Set this if you don't want to allow all IP addresses to access this
#   encrypted channel. This only makes sense for servers.
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
  $connect,
  $accept,
  $client = true,
  $failover = 'rr',
  $sni = false,
  $key = "/etc/pki/private/${::fqdn}.pem",
  $cert = "/etc/pki/public/${::fqdn}.pub",
  $ca_path = '/etc/pki/cacerts',
  $crl_path = '/etc/pki/crl',
  $ciphers = ['HIGH','-SSLv2'],
  $curve = false,
  $ssl_version = false,
  $options = [],
  $verify = '2',
  $ocsp = false,
  $ocsp_flags = [],
  $local = false,
  $protocol = false,
  $protocol_authentication = false,
  $protocol_host = false,
  $protocol_password = false,
  $protocol_username = false,
  $delay = false,
  $engine_num = false,
  $libwrap = false,
  $exec = false,
  $execargs = [],
  $pty = false,
  $renegotiation = true,
  $reset = true,
  $retry = false,
  $session_cache_size = false,
  $session_cache_timeout = false,
  $stack = false,
  $timeout_busy = false,
  $timeout_close = false,
  $timeout_connect = false,
  $timeout_idle = false,
  $client_nets = 'any',
  $use_iptables = true
) {
  include 'stunnel'

  concat_fragment { "stunnel+stunnel_${name}.conf":
    content => template('stunnel/stunnel.erb')
  }

  # The rules are pulled together from the accept_* and connect_*
  # variables.
  #
  # This is only enabled if the system is a server.
  if $use_iptables and !$client {
    include 'iptables'

    $dport = split($accept,':')

    iptables::add_tcp_stateful_listen { "allow_stunnel_${name}":
      client_nets => $client_nets,
      dports      => $dport[-1]
    }
  }

  if $libwrap and !$client {
    include 'tcpwrappers'

    tcpwrappers::allow { "allow_stunnel_${name}":
      pattern => nets2ddq($client_nets)
    }
  }

  validate_array($connect)
  validate_re_array($connect,'^(.+:)?\d+$')
  validate_re($accept,'^(.+:)?\d+$')
  validate_bool($client)
  validate_array_member($failover,['rr','prio'])
  validate_absolute_path($key)
  validate_absolute_path($cert)
  validate_absolute_path($ca_path)
  validate_absolute_path($crl_path)
  validate_array($ciphers)
  validate_array($options)
  validate_between($verify, 0, 4)
  if $ocsp { validate_re($ocsp,'^https?://.+$') }
  if !empty($ocsp_flags) {
    validate_re_array($ocsp_flags,[
      'NOCERTS', 'NOINTERN', 'NOSIGS', 'NOCHAIN', 'NOVERIFY', 'NOEXPLICIT',
      'NOCASIGN', 'NODELEGATED', 'NOCHECKS', 'TRUSTOTHER',
      'RESPID_KEY', 'NOTIME'])
  }
  if $local { validate_net_list($local) }
  if $protocol_authentication { validate_array_member($protocol_authentication,['basic','NTLM']) }
  if $protocol_password { validate_string($protocol_password) }
  if $protocol_username { validate_string($protocol_username) }
  if $delay { validate_bool($delay) }
  if $pty { validate_bool($pty) }
  validate_bool($renegotiation)
  validate_bool($reset)
  validate_bool($retry)
  if $session_cache_timeout { validate_integer($session_cache_timeout) }
  if $stack { validate_integer($stack) }
  if $timeout_busy { validate_integer($timeout_busy) }
  if $timeout_close { validate_integer($timeout_close) }
  if $timeout_connect { validate_integer($timeout_connect) }
  if $timeout_idle { validate_integer($timeout_idle) }
  validate_net_list($client_nets,'^any$')
  validate_bool($use_iptables)

  compliance_map()

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
    if $sni { validate_re($sni,'^.+(:.+)?$') }
    if $curve { validate_string($curve) }
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
    if $engine_num { validate_integer($engine_num) }
    validate_bool($libwrap)
    if $session_cache_size { validate_integer($session_cache_size) }
  }
}
