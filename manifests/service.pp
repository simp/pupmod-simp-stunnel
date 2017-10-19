# Manage the Stunnel Service
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowswki@keywcorp.com>
#
class stunnel::service {

  if 'systemd' in $facts['init_systems'] {
    service { 'stunnel':
      ensure  => running,
      require => File['/etc/systemd/system/stunnel.service']
    }
  } else {
    service { 'stunnel':
      ensure  => 'running',
      require => File['/etc/rc.d/init.d/stunnel'],
    }
  }
}
