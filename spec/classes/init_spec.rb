require 'spec_helper'

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
  it { is_expected.to contain_simpcat_build('stunnel') }
  it { is_expected.to contain_file('/etc/stunnel').with_group('stunnel') }
  it { is_expected.to contain_file('/etc/stunnel/stunnel.conf') }

  # Service
  it { is_expected.to create_class('stunnel::service').that_comes_before('Class[stunnel]') }
  it { is_expected.to create_file('/etc/rc.d/init.d/stunnel').that_notifies('Exec[stunnel_chkconfig_update]') }
  it { is_expected.to contain_service('stunnel').that_requires('File[/etc/rc.d/init.d/stunnel]') }
  it { is_expected.to contain_exec('stunnel_chkconfig_update') }
end

# This is used in a regex, put common items to be matched here.
$stunnel_conf = <<-EOM
# This file managed by Puppet. Manual changes will be erased!

setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel.pid
engine = auto
EOM

describe 'stunnel' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts){ facts }

        context 'with default parameters (chrooted)' do
          it_should_behave_like "a chrooted and non-chrooted configuration"

          # Specific to chrooting
          it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/#{$stunnel_conf_chrooted}/) }
          it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/chroot = \/var\/stunnel/) }
          # Fips should be disabled with default params
          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/fips = no/) }
          # Fips should not exist on an el 6 system
          else
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').without_content(/fips/) }
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
          let(:params) {{:selinux => true}}
          it_should_behave_like "a chrooted and non-chrooted configuration"

          # Specific to chrooting
          it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/#{$stunnel_conf_chrooted}/) }
          it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/chroot = false/) }
          # Fips should be disabled with default params
          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/fips = no/) }
          # Fips should not exist on an el 6 system
          else
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').without_content(/fips/) }
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
          it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/syslog = yes/) }
          # Fips should be enabled on el 7 systems
          if facts[:osfamily] == 'RedHat' && facts[:operatingsystemmajrelease] >= '7'
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').with_content(/fips = yes/) }
          # Fips should not exist on an el 6 system
          else
            it { is_expected.to contain_simpcat_fragment('stunnel+0global.conf').without_content(/fips/) }
          end
        end
      end
    end
  end
end
