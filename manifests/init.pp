# Set up stunnel
#
# @param pki
#   * If 'simp', include SIMP's pki module and use pki::copy to manage
#     application certs in /etc/pki/simp_apps/stunnel/x509
#   * If true, do *not* include SIMP's pki module, but still use pki::copy
#     to manage certs in /etc/pki/simp_apps/stunnel/x509
#   * If false, do not include SIMP's pki module and do not use pki::copy
#     to manage certs.  You will need to appropriately assign a subset of:
#     * app_pki_dir
#     * app_pki_key
#     * app_pki_cert
#     * app_pki_ca
#     * app_pki_ca_dir
#
# @param app_pki_external_source
#   * If pki = 'simp' or true, this is the directory from which certs will be
#     copied, via pki::copy.  Defaults to /etc/pki/simp/x509.
#
#   * If pki = false, this variable has no effect.
#
# @param app_pki_dir
#   This variable controls the source of certs in the chroot, and the basepath
#   of $app_pki_key, $app_pki_cert, $app_pki_ca, $app_pki_ca_dir, and
#   $app_pki_crl. It defaults to /etc/pki/simp_apps/stunnel/x509.
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
#   from an external source.
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
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowski@keywcorp.com>
#
class stunnel (
  Stdlib::Absolutepath          $app_pki_dir             = '/etc/pki/simp_apps/stunnel/x509',
  Stdlib::Absolutepath          $app_pki_external_source = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Stdlib::Absolutepath          $app_pki_key             = "${app_pki_dir}/private/${facts['fqdn']}.pem",
  Stdlib::Absolutepath          $app_pki_cert            = "${app_pki_dir}/public/${facts['fqdn']}.pub",
  Stdlib::Absolutepath          $app_pki_ca_dir          = "${app_pki_dir}/cacerts",
  Stdlib::Absolutepath          $app_pki_crl             = "${app_pki_dir}/crl",
  String                        $setuid                  = 'stunnel',
  String                        $setgid                  = 'stunnel',
  Boolean                       $syslog                  = simplib::lookup('simp_options::syslog', { 'default_value'      => false }),
  Boolean                       $fips                    = simplib::lookup('simp_options::fips', { 'default_value'        => false }),
  Boolean                       $haveged                 = simplib::lookup('simp_options::haveged', { 'default_value'     => false }),
  Variant[Enum['simp'],Boolean] $pki                     = simplib::lookup('simp_options::pki', { 'default_value'         => false })
) {
  if $haveged { include '::haveged' }

  contain '::stunnel::install'
  contain '::stunnel::config'
  contain '::stunnel::service'

  Class['stunnel::install'] -> Class['stunnel::config']
  Class['stunnel::config'] ~> Class['stunnel::service']
}
