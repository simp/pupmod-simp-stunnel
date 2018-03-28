# Manage the Stunnel Service
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::service {

  if 'systemd' in $facts['init_systems'] {
    file { '/etc/rc.d/init.d/stunnel': ensure => 'absent' }

    service { 'stunnel':
      ensure  => running,
      enable  => true,
      require => [
        File['/etc/systemd/system/stunnel.service'],
        File['/etc/rc.d/init.d/stunnel']
      ]
    }
  } else {
    # The script takes care of chkconfig
    service { 'stunnel':
      ensure  => running,
      enable  => true,
      require => File['/etc/rc.d/init.d/stunnel']
    }
  }
}
