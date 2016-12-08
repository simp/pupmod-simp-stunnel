# == Class: stunnel
#
# Set up stunnel.
#
# == Parameters
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
# [*syslog*]
#   Type: Boolean
#   Default: true
#
#   Whether or not to log to syslog.
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
# [*haveged*]
#   Type: Boolean
#   Default: false
#
#   If true, include SIMP haveged module to assist with entropy generation.
#
# [*pki*]
#   Type: Boolean
#   Default: false
#
#   If true, use the SIMP PKI module for key management.
#
# [*selinux*]
#   Type: Boolean
#   Default: false
#
#   If true, use the SIMP Selinux module for context enforcement.
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
# * Nick Markowski <nmarkowski@keywcorp.com>
#
class stunnel (
  Stdlib::Absolutepath  $app_pki_dir    = '/var/stunnel_pki',
  Stdlib::Absolutepath  $app_pki_key    = "/var/stunnel_pki/pki/private/${::fqdn}.pem",
  Stdlib::Absolutepath  $app_pki_cert   = "/var/stunnel_pki/pki/public/${::fqdn}.pub",
  Stdlib::Absolutepath  $app_pki_ca_dir = '/var/stunnel_pki/pki/cacerts',
  Stdlib::Absolutepath  $app_pki_crl    = '/var/stunnel_pki/pki/crl',
  String                $setuid         = 'stunnel',
  String                $setgid         = 'stunnel',
  Boolean               $selinux        = simplib::lookup('simp_options::selinux', { 'default_value' => false }),
  Boolean               $syslog         = simplib::lookup('simp_options::syslog', { 'default_value'  => false }),
  Boolean               $fips           = simplib::lookup('simp_options::fips', { 'default_value'    => false }),
  Boolean               $haveged        = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean               $pki            = simplib::lookup('simp_options::pki', { 'default_value'     => false })
) {

  if $haveged {
    include '::haveged'
  }

  include '::stunnel::install'
  include '::stunnel::config'
  include '::stunnel::service'

  Class['stunnel::install'] ->
  Class['stunnel::config'] ~>
  Class['stunnel::service'] ->
  Class['stunnel']
}
