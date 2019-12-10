# @summary Purge `stunnel::instance` resources that were previously managed by this module
#
# The native type has an `autobefore` that will ensure ordering.
#
# It is **highly recommended** that you always include this class if you have
# ever used the stunnel defined types. If you choose not to, then you will
# likely have stunnel instance processes that remain on your system and which
# may not function properly.
#
# @param purge_dirs
#   The directories to search for files to purge
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::instance_purge (
  Array[Stdlib::Absolutepath] $purge_dirs = [ '/etc/stunnel',
                                              '/etc/rc.d/init.d',
                                              '/etc/systemd/system'
                                            ]
) {
  stunnel_instance_purge { 'stunnel_managed_by_puppet':
    dirs => $purge_dirs
  }
}
