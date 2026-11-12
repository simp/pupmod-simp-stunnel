# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) Defined Type**
#
# Install the Stunnel components
#
# @param version
#   The version of stunnel to install
#
#   * Accepts anything that the ``ensure`` parameter of the ``package``
#     resource can handle
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::install (
  Variant[String, Integer] $version = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' })
) {
  assert_private()

  if $stunnel::haveged {
    deprecation(
      'stunnel::haveged',
      "${module_name}: 'stunnel::haveged' is deprecated and will be removed in the next major release. Use 'stunnel::rngd' instead.",
      false
    )
    simplib::assert_optional_dependency($module_name, 'simp/haveged')

    include 'haveged'
  }

  if $stunnel::rngd { include 'rngd' }

  package { 'stunnel': ensure => $version }

  file { '/etc/stunnel':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Package['stunnel'],
  }
}
