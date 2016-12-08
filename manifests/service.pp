# == Class stunnel::service
#
# == Authors
#
# * Trevor Vaughan <tvaughan@onyxpoint.com>
# * Nick Markowski <nmarkowswki@keywcorp.com>
#
class stunnel::service {

  file { '/etc/rc.d/init.d/stunnel':
    ensure => 'present',
    owner  => 'root',
    group  => 'root',
    mode   => '0750',
    source => 'puppet:///modules/stunnel/stunnel',
    tag    => 'firstrun',
    notify => Exec['stunnel_chkconfig_update'],
  }

  service { 'stunnel':
    ensure     => 'running',
    hasrestart => true,
    hasstatus  => true,
    require    =>  File['/etc/rc.d/init.d/stunnel'],
    tag        => 'firstrun'
  }

  exec { 'stunnel_chkconfig_update':
    command     => '/sbin/chkconfig --del stunnel; /sbin/chkconfig --add stunnel',
    refreshonly => true,
  }
}
