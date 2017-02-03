# Manage the Stunnel Service
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Nick Markowski <nmarkowswki@keywcorp.com>
#
class stunnel::service {

  file { '/etc/rc.d/init.d/stunnel':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    content => file("${module_name}/stunnel.init"),
    tag     => 'firstrun',
    notify  => Exec['stunnel_chkconfig_update'],
  }

  exec { 'stunnel_chkconfig_update':
    command     => '/sbin/chkconfig --del stunnel; /sbin/chkconfig --add stunnel',
    refreshonly => true,
    before      => Service['stunnel']
  }

  service { 'stunnel':
    ensure     => 'running',
    hasrestart => true,
    hasstatus  => true,
    require    => File['/etc/rc.d/init.d/stunnel'],
    tag        => 'firstrun'
  }
}
