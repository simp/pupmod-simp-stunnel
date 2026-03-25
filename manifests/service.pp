# Manage the Stunnel Service
#
# @author https://github.com/simp/pupmod-simp-stunnel/graphs/contributors
#
class stunnel::service {
  if 'systemd' in $facts['init_systems'] {
    file { '/etc/rc.d/init.d/stunnel': ensure => 'absent' }

    service { 'stunnel':
      ensure    => running,
      enable    => true,
      subscribe => Systemd::Unit_file['stunnel.service'],
      require   => [
        File['/etc/rc.d/init.d/stunnel']
      ],
    }
  } else {
    fail("Init systems ${facts['init_systems']} not supported. Only 'systemd' is supported.")
  }
}
