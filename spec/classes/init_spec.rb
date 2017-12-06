require 'spec_helper'

describe 'stunnel' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts){ os_facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('stunnel') }
        it { is_expected.to_not create_class('haveged') }
        it { is_expected.to create_class('stunnel::install') }
        it { is_expected.to create_package('stunnel').with_ensure('installed') }
        it { is_expected.to create_file('/etc/stunnel').with({
            :ensure => 'directory',
            :owner  => 'root',
            :group  => 'root',
            :mode   => '0644'
          }).that_requires('Package[stunnel]')
        }
        it { is_expected.to create_stunnel_instance_purge('stunnel_managed_by_puppet').with_dirs([
            '/etc/stunnel',
            '/etc/rc.d/init.d',
            '/etc/systemd/system'
          ])
        }

        context 'with haveged included' do
          let(:params){{
            :haveged => true
          }}

          it { is_expected.to create_class('haveged') }
        end
      end
    end
  end
end
