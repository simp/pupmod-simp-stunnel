# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) DEFINED TYPE**
#
# This is a 'canary' defined type that allow us to fail a compile in the case
# that the `stunnel::interface` and `stunnel::connection` defined types have an
# overlapping listen port.
#
define stunnel::instance::reserve_port {
  assert_private()
}
