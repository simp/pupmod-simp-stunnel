require 'spec_helper'

describe 'stunnel' do

  shared_examples_for "a chrooted and non-chrooted configuration" do
    # Init
    it { is_expected.to create_class('stunnel') }
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to_not contain_class('haveged') }

    # Install
    it { is_expected.to create_class('stunnel::install').that_comes_before('Class[stunnel::config]') }
    it { is_expected.to create_group('stunnel') }
    it { is_expected.to create_user('stunnel') }
    it { is_expected.to create_package('stunnel').with_require(["User[stunnel]","Group[stunnel]"]) }

    # Config
    it { is_expected.to create_class('stunnel::config') }
    it { is_expected.to_not contain_class('pki') }
    it { is_expected.to contain_concat('/etc/stunnel/stunnel.conf') }
    it { is_expected.to contain_file('/etc/stunnel').with_group('stunnel') }

    # Service
    it { is_expected.to create_class('stunnel::service') }
    it { is_expected.to create_file('/etc/rc.d/init.d/stunnel').that_notifies('Exec[stunnel_chkconfig_update]') }
    it { is_expected.to contain_service('stunnel').that_requires('File[/etc/rc.d/init.d/stunnel]') }
    it { is_expected.to contain_exec('stunnel_chkconfig_update') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
          let(:facts){
            _facts = facts.dup
            _facts[:selinux_current_mode] = 'disabled'

            _facts
          }

        context 'with default parameters (chrooted) and selinux off' do
          it_should_behave_like "a chrooted and non-chrooted configuration"

          # Specific to chrooting
          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            # Fips should be disabled with default params for el 7 systems
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM
# This file managed by Puppet. Manual changes will be erased!

chroot = /var/stunnel
setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel.pid
engine = auto
fips = no
              EOM
            )}
          else
            # Fips should not exist on an el 6 system
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM
# This file managed by Puppet. Manual changes will be erased!

chroot = /var/stunnel
setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel.pid
engine = auto
              EOM
            )}
          end

          it { is_expected.to contain_file('/var/stunnel') }
          it { is_expected.to contain_file('/var/stunnel/etc') }
          it { is_expected.to contain_file('/var/stunnel/etc/resolv.conf') }
          it { is_expected.to contain_file('/var/stunnel/etc/nsswitch.conf') }
          it { is_expected.to contain_file('/var/stunnel/etc/hosts') }
          it { is_expected.to contain_file('/var/stunnel/var') }
          it { is_expected.to contain_file('/var/stunnel/var/run') }
          it { is_expected.to contain_file('/var/stunnel/var/run/stunnel') }
          it { is_expected.to contain_file('/var/stunnel/etc/pki') }
          it { is_expected.to contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///var/stunnel_pki/pki/cacerts') }

        end

        context 'with selinux = true (non-chrooted)' do
          let(:facts){ facts }

          it_should_behave_like "a chrooted and non-chrooted configuration"

          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            # Fips should be disabled
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM
# This file managed by Puppet. Manual changes will be erased!

setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel.pid
engine = auto
fips = no
              EOM
            )}
          else
            # Fips should not exist on an el 6 system
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM
# This file managed by Puppet. Manual changes will be erased!

setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel.pid
engine = auto
              EOM
            )}
          end
          it { is_expected.to_not contain_file('/var/stunnel') }
          it { is_expected.to_not contain_file('/var/stunnel/etc') }
          it { is_expected.to_not contain_file('/var/stunnel/etc/resolv.conf') }
          it { is_expected.to_not contain_file('/var/stunnel/etc/nsswitch.conf') }
          it { is_expected.to_not contain_file('/var/stunnel/etc/hosts') }
          it { is_expected.to_not contain_file('/var/stunnel/var') }
          it { is_expected.to_not contain_file('/var/stunnel/var/run') }
          it { is_expected.to_not contain_file('/var/stunnel/var/run/stunnel') }
          it { is_expected.to_not contain_file('/var/stunnel/etc/pki') }
          it { is_expected.to_not contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///var/stunnel_pki/pki/cacerts') }
        end
        context 'with pki = true, haveged = true, syslog = true, and fips = true' do
          let(:params) {{
            :pki => true,
            :haveged => true,
            :syslog => true,
            :fips => true
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('pki') }
          it { is_expected.to create_file('/var/stunnel_pki') }
          it { is_expected.to create_pki__copy('/var/stunnel_pki') }
          # Make sure syslog = yes in stunnel.conf
          it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(/syslog = yes/) }
          # Fips should be enabled on el 7 systems
          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(/fips = yes/) }
          # Fips should not exist on an el 6 system
          else
            it { is_expected.to contain_concat__fragment('0_stunnel_global').without_content(/fips/) }
          end
        end
      end
    end
  end
end
