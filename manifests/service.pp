# Manage the Stunnel Service
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::service {

  if 'systemd' in $facts['init_systems'] {
    service { 'stunnel':
      ensure  => running,
      enable  => true,
      require => File['/etc/systemd/system/stunnel.service']
    }
  } else {
    # The script takes care of chkconfig
    service { 'stunnel':
      ensure  => running,
      require => File['/etc/rc.d/init.d/stunnel'],
    }
  }
}
