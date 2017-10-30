require 'spec_helper'

describe 'stunnel' do

  shared_examples_for "a chrooted and non-chrooted configuration" do
    # Init
    it { is_expected.to create_class('stunnel') }
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to_not contain_class('haveged') }

    # User
    it { is_expected.to create_stunnel__account('stunnel').that_comes_before('Class[stunnel::config]') }

    # Install
    it { is_expected.to create_class('stunnel::install').that_comes_before('Stunnel::Account[stunnel]') }
    it { is_expected.to create_group('stunnel') }
    it { is_expected.to create_user('stunnel') }
    it { is_expected.to create_package('stunnel') }

    # Config
    it { is_expected.to create_class('stunnel::config') }
    it { is_expected.to_not contain_class('pki') }
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
        let(:facts) {
          os_facts.merge(
            selinux_current_mode: 'disabled',
            selinux_enforced: false
          )
        }

        context 'with default parameters (chrooted) and selinux off' do
          it_should_behave_like "a chrooted and non-chrooted configuration"

          # Specific to chrooting
          if os_facts[:operatingsystemmajrelease] >= '7'
            # Fips should be disabled with default params for el 7 systems
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(/^\s+/,'')
                chroot = /var/stunnel
                setgid = stunnel
                setuid = stunnel
                debug = err
                syslog = no
                foreground = yes
                pid =
                engine = auto
                fips = no
              EOM
            )}
          else
            # Fips should not exist on an el 6 system
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(/^\s+/,'')
                chroot = /var/stunnel
                setgid = stunnel
                setuid = stunnel
                debug = err
                syslog = no
                foreground = no
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
          it { is_expected.to contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///etc/pki/simp_apps/stunnel/x509/cacerts') }

          if os_facts[:operatingsystemmajrelease].to_i >= 7
            let(:service_file) { File.read('spec/expected/connection/chroot-systemd.txt') }
            it { is_expected.to create_file('/etc/systemd/system/stunnel.service') \
              .that_notifies('Exec[stunnel daemon reload]') \
              .with_content(service_file) }
            it { is_expected.to contain_service('stunnel') \
              .that_requires('File[/etc/systemd/system/stunnel.service]') }
            it { is_expected.to contain_exec('stunnel daemon reload') }
          else
            let(:service_file) { File.read('spec/expected/connection/chroot-init.txt') }
            it { is_expected.to create_file('/etc/rc.d/init.d/stunnel').with_content(service_file) }
            it { is_expected.to contain_service('stunnel').that_requires('File[/etc/rc.d/init.d/stunnel]') }
          end
        end

        context 'with selinux = true (non-chrooted)' do
          let(:facts) {
            os_facts.merge(
              selinux_current_mode: 'enforced',
              selinux_enforced: true
            )
          }

          it_should_behave_like "a chrooted and non-chrooted configuration"

          if os_facts[:operatingsystemmajrelease] >= '7'
            # Fips should be disabled
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(/^\s+/,'')
                setgid = stunnel
                setuid = stunnel
                debug = err
                syslog = no
                foreground = yes
                pid =
                engine = auto
                fips = no
              EOM
            )}
          else
            # Fips should not exist on an el 6 system
            it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(<<-EOM.gsub(/^\s+/,'')
                setgid = stunnel
                setuid = stunnel
                debug = err
                syslog = no
                foreground = no
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
          it { is_expected.to_not contain_file('/var/stunnel/etc/pki/cacerts').with_source('file:///etc/pki/simp_apps/stunnel/x509/cacerts') }

          if os_facts[:operatingsystemmajrelease].to_i >= 7
            let(:service_file) { File.read('spec/expected/connection/nonchroot-systemd.txt') }
            it { is_expected.to create_file('/etc/systemd/system/stunnel.service') \
              .that_notifies('Exec[stunnel daemon reload]') \
              .with_content(service_file) }
            it { is_expected.to contain_service('stunnel') \
              .that_requires('File[/etc/systemd/system/stunnel.service]') }
            it { is_expected.to contain_exec('stunnel daemon reload') }
          else
            let(:service_file) { File.read('spec/expected/connection/nonchroot-init.txt') }
            it { is_expected.to create_file('/etc/rc.d/init.d/stunnel').with_content(service_file) }
            it { is_expected.to contain_service('stunnel').that_requires('File[/etc/rc.d/init.d/stunnel]') }
          end
        end
        context 'with pki = simp, haveged = true, syslog = true, and fips = true' do
          let(:params) {{
            pki:     'simp',
            haveged: true,
            syslog:  true,
            fips:    true
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('pki') }
          it { is_expected.to create_pki__copy('stunnel') }
          # Make sure syslog = yes in stunnel.conf
          it { is_expected.to contain_concat__fragment('0_stunnel_global').with_content(/syslog = yes/) }
          # Fips should be enabled on el 7 systems
          if os_facts[:operatingsystemmajrelease] >= '7'
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
