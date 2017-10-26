# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
# A define for setting up stunnel service users and groups
#
# This is necessary so that services using the same user and group can
# successfully be spawned via a define.
#
# @param name
#   The user name for the account
#
# @param groupname
#   The group name for the account
#
# @param uid
#   The UID of the user
#
# @param gid
#   The GID of the user
#
# @param home
#   The home directory of the user
#
# @param shell
#   The shell for the user
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
define stunnel::account (
  String               $groupname = $name,
  Integer              $uid       = 600,
  Integer              $gid       = 600,
  Stdlib::Absolutepath $home      = '/var/run/stunnel',
  Stdlib::Absolutepath $shell     = '/sbin/nologin'
) {
  assert_private()

  $_user = {
    $name          => {
      'ensure'     => 'present',
      'allowdupe'  => false,
      'uid'        => $uid,
      'gid'        => $gid,
      'home'       => $home,
      'managehome' => false,
      'membership' => 'inclusive',
      'shell'      => '/sbin/nologin'
    }
  }

  $_group = {
    $groupname    => {
      'ensure'    => 'present',
      'allowdupe' => false,
      'gid'       =>  $gid
    }
  }

  ensure_resources('user', $_user)
  ensure_resources('group', $_group)
}
