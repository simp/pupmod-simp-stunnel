# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# This is simply present to isolate the logic of the installation from the
# internals
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
