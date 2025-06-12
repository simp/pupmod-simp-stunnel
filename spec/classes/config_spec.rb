require 'spec_helper'

describe 'stunnel::config' do
  def mock_selinux_false_facts(os_facts)
    os_facts[:selinux] = false
    os_facts[:os][:selinux][:config_mode] = 'disabled'
    os_facts[:os][:selinux][:current_mode] = 'disabled'
    os_facts[:os][:selinux][:enabled] = false
    os_facts[:os][:selinux][:enforced] = false
    os_facts
  end

  def mock_selinux_enforcing_facts(os_facts)
    os_facts[:selinux] = true
    os_facts[:os][:selinux][:config_mode] = 'enforcing'
    os_facts[:os][:selinux][:config_policy] = 'targeted'
    os_facts[:os][:selinux][:current_mode] = 'enforcing'
    os_facts[:os][:selinux][:enabled] = true
    os_facts[:os][:selinux][:enforced] = true
    os_facts
  end

  shared_examples_for 'a chrooted and non-chrooted configuration' do
    # Init
    it { is_expected.to create_class('stunnel') }
    it { is_expected.to compile.with_all_deps }

    # User
    it { is_expected.to create_stunnel__account('stunnel') }

    # Install
    it { is_expected.to create_class('stunnel::install') }
    it { is_expected.to create_group('stunnel') }
    it { is_expected.to create_user('stunnel') }
    it { is_expected.to create_package('stunnel') }

    # Config
    it { is_expected.to create_class('stunnel::config') }
    it { is_expected.not_to contain_class('pki') }
    it { is_expected.to contain_concat('/etc/stunnel/stunnel.conf') }
    it { is_expected.to contain_file('/etc/stunnel').with_owner('root') }
    it { is_expected.to contain_file('/etc/stunnel').with_group('root') }
    it { is_expected.to contain_file('/etc/stunnel').with_mode('0644') }

    # Service
    it { is_expected.to create_class('stunnel::service') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          mock_selinux_false_facts(os_facts)
        end

        context 'with default parameters (chrooted) and selinux off' do
          let(:service_file) { File.read('spec/expected/connection/chroot-systemd.txt') }

          it_behaves_like 'a chrooted and non-chrooted configuration'

          # Specific to chrooting
          it {
            is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(%r{^\s+}, ''),
              chroot = /var/stunnel
              setgid = stunnel
              setuid = stunnel
              debug = err
              syslog = no
              foreground = yes
              pid = /var/run/stunnel/stunnel.pid
              engine = auto
              fips = no
              RNDoverwrite = yes
            EOM
                                                                                    )
          }

          it { is_expected.to contain_file('/var/stunnel') }
          it { is_expected.to contain_file('/var/stunnel/etc') }
          it { is_expected.to contain_file('/var/stunnel/etc/resolv.conf') }
          it { is_expected.to contain_file('/var/stunnel/etc/nsswitch.conf') }
          it { is_expected.to contain_file('/var/stunnel/etc/hosts') }
          it { is_expected.to contain_file('/var/stunnel/var') }
          it { is_expected.to contain_file('/var/stunnel/var/run') }
          it { is_expected.to contain_file('/var/stunnel/var/run/stunnel') }
          it { is_expected.to contain_file('/var/stunnel/etc/pki') }
          it { is_expected.to contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///etc/pki/simp_apps/stunnel/x509/cacerts') }
          it {
            is_expected.to create_file('/etc/systemd/system/stunnel.service')
              .that_notifies('Exec[stunnel daemon reload]')
              .with_content(service_file)
          }
          it { is_expected.to contain_file('/etc/rc.d/init.d/stunnel').with_ensure('absent') }
          it {
            is_expected.to contain_service('stunnel')
              .that_requires(['File[/etc/systemd/system/stunnel.service]', 'File[/etc/rc.d/init.d/stunnel]'])
          }
          it { is_expected.to contain_exec('stunnel daemon reload') }
        end

        context 'with parameters chroot set to /' do
          let(:params) do
            {
              chroot:     '/',
            }
          end

          it 'is expected to fail' do
            expect { catalogue }.to raise_error Puppet::Error, %r{chroot should not be root}
          end
        end

        context 'with selinux = true (non-chrooted)' do
          let(:facts) do
            mock_selinux_enforcing_facts(os_facts)
          end
          let(:service_file) { File.read('spec/expected/connection/nonchroot-systemd.txt') }

          it_behaves_like 'a chrooted and non-chrooted configuration'

          # Fips should be disabled
          it {
            is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(%r{^\s+}, ''),
              setgid = stunnel
              setuid = stunnel
              debug = err
              syslog = no
              foreground = yes
              pid = /var/run/stunnel/stunnel.pid
              engine = auto
              fips = no
              RNDoverwrite = yes
            EOM
                                                                                    )
          }
          it { is_expected.not_to contain_file('/var/stunnel') }
          it { is_expected.not_to contain_file('/var/stunnel/etc') }
          it { is_expected.not_to contain_file('/var/stunnel/etc/resolv.conf') }
          it { is_expected.not_to contain_file('/var/stunnel/etc/nsswitch.conf') }
          it { is_expected.not_to contain_file('/var/stunnel/etc/hosts') }
          it { is_expected.not_to contain_file('/var/stunnel/var') }
          it { is_expected.not_to contain_file('/var/stunnel/var/run') }
          it { is_expected.not_to contain_file('/var/stunnel/var/run/stunnel') }
          it { is_expected.not_to contain_file('/var/stunnel/etc/pki') }
          it { is_expected.not_to contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///etc/pki/simp_apps/stunnel/x509/cacerts') }

          it {
            is_expected.to create_file('/etc/systemd/system/stunnel.service')
              .that_notifies('Exec[stunnel daemon reload]')
              .with_content(service_file)
          }
          it {
            is_expected.to contain_service('stunnel')
              .that_requires('File[/etc/systemd/system/stunnel.service]')
          }
          it { is_expected.to contain_exec('stunnel daemon reload') }
        end
        context 'with pki = simp, syslog = true, and fips = true' do
          let(:params) do
            {
              pki:     'simp',
           syslog:  true,
           fips:    true
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('pki') }
          it { is_expected.to create_pki__copy('stunnel') }
          # Make sure syslog = yes in stunnel.conf
          it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(%r{syslog = yes}) }
          it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(%r{fips = yes}) }
        end

        context 'with pid specified' do
          # Change a param to force a recompile and full hiera lookup
          let(:params) do
            {
              fips: true
            }
          end
          let(:service_file) { File.read('spec/expected/connection/chroot-systemd-pid.txt') }

          # I have to go to hiera for this...
          # stunnel::config::pid: /var/opt/run/stunnel.pid
          let(:hieradata) { 'pid' }

          it { is_expected.to compile.with_all_deps }

          it {
            is_expected.to contain_file('/etc/systemd/system/stunnel.service')
              .with_content(service_file)
          }
        end
      end
    end
  end
end
