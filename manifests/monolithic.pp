# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Prevent global connection and configuration from being instantiated when only
# stunnel::instance resources are required.
class stunnel::monolithic {
  assert_private()

  include '::stunnel'

  contain '::stunnel::config'
  contain '::stunnel::service'

  Class['stunnel::config'] ~> Class['stunnel::service']

  if $::stunnel::haveged {
    Class['haveged'] ~> Class['stunnel::service']
  }
}
