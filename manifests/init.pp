# Set up stunnel
#
# @param app_pki_dir
#   If ``$pki`` is ``true``, certs will be copied to this location for stunnel
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
#   * This should be the full path to a directory containing **hashed
#     versions** of the CA certificates
#
# @param app_pki_crl
#     Since stunnel runs in a chroot, you need to copy the appropriate CRL in
#     from an external source
#
# @param setuid
#   The user stunnel should run as
#
# @param setgid
#   The group stunnel should run as
#
# @param syslog
#   Whether or not to log to syslog
#
# @param fips
#   Set the fips global option
#
#   * We don't enable FIPS mode by default since we want to be able to use
#     TLS1.2
#
#   * **NOTE:** This has no effect on EL < 7 due to stunnel not accepting the
#     fips option in that version of stunnel.
#
# @param haveged
#  Include the SIMP ``haveged`` module to assist with entropy generation
#
# @param pki
#   Use the SIMP ``pki`` module for key management
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowski@keywcorp.com>
#
class stunnel (
  Stdlib::Absolutepath  $app_pki_dir    = '/var/stunnel_pki',
  Stdlib::Absolutepath  $app_pki_key    = "/var/stunnel_pki/pki/private/${::fqdn}.pem",
  Stdlib::Absolutepath  $app_pki_cert   = "/var/stunnel_pki/pki/public/${::fqdn}.pub",
  Stdlib::Absolutepath  $app_pki_ca_dir = '/var/stunnel_pki/pki/cacerts',
  Stdlib::Absolutepath  $app_pki_crl    = '/var/stunnel_pki/pki/crl',
  String                $setuid         = 'stunnel',
  String                $setgid         = 'stunnel',
  Boolean               $syslog         = simplib::lookup('simp_options::syslog', { 'default_value'  => false }),
  Boolean               $fips           = simplib::lookup('simp_options::fips', { 'default_value'    => false }),
  Boolean               $haveged        = simplib::lookup('simp_options::haveged', { 'default_value' => false }),
  Boolean               $pki            = simplib::lookup('simp_options::pki', { 'default_value'     => false })
) {
  if $haveged { include '::haveged' }

  contain '::stunnel::install'
  contain '::stunnel::config'
  contain '::stunnel::service'

  Class['stunnel::install'] -> Class['stunnel::config']
  Class['stunnel::config'] ~> Class['stunnel::service']
}
