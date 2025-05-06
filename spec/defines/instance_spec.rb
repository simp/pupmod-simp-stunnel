require 'spec_helper'

describe 'stunnel::instance' do
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

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:title) { 'nfs' }
      let(:facts) do
        mock_selinux_enforcing_facts(os_facts.merge(haveged__rngd_enabled: false))
      end

      context 'with default parameters' do
        let(:params) do
          {
            connect: [2049],
            accept:  '10.1.2.3:20490',
          }
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_stunnel__instance__reserve_port('20490') }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.not_to create_iptables__listen__tcp_stateful('allow_stunnel_nfs') }
        it { is_expected.not_to create_tcpwrappers__allow('allow_stunnel_nfs') }
        it { is_expected.not_to create_pki__copy('stunnel_nfs') }
        it { is_expected.not_to create_file('/var/stunnel_nfs') }
      end

      context 'with firewall, tcpwrappers, pki, fips true' do
        let(:params) do
          {
            client:       false,
            connect:      [2049],
            accept:       20_490,
            trusted_nets: ['any'],
            firewall:     true,
            tcpwrappers:  true,
            pki:          true,
            fips:         true,
          }
        end
        let(:service_file) { File.read('spec/expected/instance/nonchroot-systemd.txt') }
        let(:stunnel_conf) { File.read('spec/expected/instance/non_chroot_el7_stunnel.conf.txt') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/stunnel') }

        it {
          is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf')
            .with_content(stunnel_conf)
        }
        it {
          is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service')
            .with_content(service_file)
        }
        it {
          is_expected.to create_iptables__listen__tcp_stateful('allow_stunnel_nfs').with(
            trusted_nets: ['any'],
            dports:       [params[:accept].to_s.split(':')[-1]],
          )
        }
        it { is_expected.to create_tcpwrappers__allow('allow_stunnel_nfs').with_pattern(['ALL']) }
        it { is_expected.to create_pki__copy('stunnel_nfs') }
        it { is_expected.to contain_class('stunnel::install') }
      end

      context 'when chrooted and pki true' do
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
            pki:     true,
          }
        end
        let(:facts) do
          mock_selinux_false_facts(os_facts.merge(haveged__rngd_enabled: false))
        end
        let(:service_file) { File.read('spec/expected/instance/chroot-systemd.txt') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_nfs') }
        it {
          is_expected.to create_file('/var/stunnel_nfs/etc/pki/cacerts')
            .that_requires('Pki::Copy[stunnel_nfs]')
        }

        it {
          is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf')
            .with_content(%r{.*chroot = /var/stunnel_nfs.*})
        }
        it {
          is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service')
            .with_content(service_file)
        }
      end

      # This behavior is not recommended or supported
      context 'when chrooted and selinux enabled' do
        let(:title) { 'sel' }
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
            pki:     true,
            chroot:  '/var/stunnel_sel',
          }
        end
        let(:facts) do
          mock_selinux_enforcing_facts(os_facts.merge(haveged__rngd_enabled: false))
        end
        let(:service_file) { File.read('spec/expected/instance/chroot-sel-systemd.txt') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_sel') }
        it { is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts') }
        it {
          is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts')
            .that_requires('Pki::Copy[stunnel_sel]')
        }

        it {
          is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_sel.conf')
            .with_content(%r{.*chroot = /var/stunnel_sel.*})
        }
        it {
          is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_sel.service')
            .with_content(service_file)
        }
      end

      # Make sure there are no resource issues when including legacy stunnel
      context 'when including (legacy) stunnel' do
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
          }
        end
        let(:pre_condition) do
          <<~EOF
            stunnel::connection { 'test':
              connect => [1234],
              accept  => 1234
            }
          EOF
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel') }
        it { is_expected.to contain_class('stunnel::config') }
        it { is_expected.to contain_class('stunnel::service') }
        it { is_expected.to contain_class('stunnel::install') }

        # Ensure that conflicting connection and instances fail to compile
        context 'with conflicting instances and connections' do
          let(:pre_condition) do
            <<~EOF
              stunnel::connection { 'conflicting_test':
                connect => [1234],
                accept  => #{params[:accept]}
              }
            EOF
          end

          it {
            is_expected.to compile.and_raise_error(
              %r{Duplicate.*\s+Stunnel::Instance::Reserve_port\[#{params[:accept]}\]},
            )
          }
        end
      end

      context 'when selinux is disabled' do
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
          }
        end
        let(:facts) do
          mock_selinux_false_facts(os_facts.merge(haveged__rngd_enabled: false))
        end

        it {
          is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service')
            .without_content(%r{system_u:object_r:stunnel_var_run_t})
        }
      end

      context 'with systemd dependencies' do
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
            systemd_wantedby: ['nfs.service'],
            systemd_requiredby: ['nfs-server.service'],
          }
        end

        it {
          is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service')
            .with_content(%r{WantedBy=nfs.service})
            .with_content(%r{RequiredBy=nfs-server.service})
        }
      end

      context 'on an unsupported OS' do
        let(:params) do
          {
            connect: [2049],
            accept:  20_490,
          }
        end
        let(:facts) do
          os_facts.merge(
            haveged__rngd_enabled: false,
            init_systems: ['rc'],
          )
        end

        it { is_expected.to compile.and_raise_error(%r{Init systems.*not supported}) }
      end

      context 'with other parameters set' do
        let(:title) { 'test_tunnel' }
        let(:conf_file) { '/etc/stunnel/stunnel_managed_by_puppet_test_tunnel.conf' }
        let(:params) do
          {
            connect: [2048, 2049],
            accept: '10.1.2.3:20490',
            compression: 'zlib',
            curve: 'prime256v1',
            egd: '/some/socket/path',
            engine_ctrl: 'LOAD',
            engine_num: 1,
            exec: '/some/exec',
            execargs: ['arg1', 'arg2'],
            local: '1.2.3.4',
            options: ['SSL_OP_NETSCAPE_CHALLENGE_BUG', 'SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS'],
            output: '/some/log',
            protocol: 'connect',
            protocol_authentication: 'basic',
            protocol_host: '1.2.3.5:2050',
            protocol_password: 'some_password',
            protocol_username: 'some_user',
            rnd_bytes: 2048,
            rnd_file: '/some/random',
            rnd_overwrite: false,
            session_cache_timeout: 20,
            session_cache_size: 1000,
            sni: 'test.sni.server',
            socket_options: [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
            ssl_version: 'TLSv1',
            stack: 1024,
            timeout_busy: 5,
            timeout_close: 10,
            timeout_connect: 15,
            timeout_idle: 20,
          }
        end

        it { is_expected.to compile.with_all_deps }

        [
          %r{sni = test.sni.server},
          %r{sessionCacheTimeout = 20},
          %r{sessionCacheSize = 1000},
          %r{renegotiation = yes},
          %r{reset = yes},
          %r{compression = zlib},
          %r{curve = prime256v1},
          %r{EGD = /some/socket/path},
          %r{engineCtrl = LOAD},
          %r{engineNum = 1},
          %r{exec = /some/exec},
          %r{execargs = arg1 arg2},
          %r{local = 1.2.3.4},
          %r{options = SSL_OP_NETSCAPE_CHALLENGE_BUG},
          %r{options = SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS},
          %r{output = /some/log},
          %r{protocol = connect},
          %r{protocolAuthentication = basic},
          %r{protocolHost = 1\.2\.3\.5:2050},
          %r{protocolPassword = some_password},
          %r{protocolUsername = some_user},
          %r{pty = no},
          %r{retry = no},
          %r{RNDbytes = 2048},
          %r{RNDfile = /some/random},
          %r{RNDoverwrite = no},
          %r{socket = l:SO_LINGER=1:60},
          %r{socket = r:TCP_NODELAY=1},
          %r{sslVersion = TLSv1},
          %r{stack = 1024},
          %r{TIMEOUTbusy = 5},
          %r{TIMEOUTclose = 10},
          %r{TIMEOUTconnect = 15},
          %r{TIMEOUTidle = 20},
        ].each do |exp_regex|
          it { is_expected.to create_file(conf_file).with_content(exp_regex) }
        end
      end

      context 'with Hiera overrides' do
        let(:pre_condition) do
          <<~EOM
            stunnel::instance{ 'nfs_client':
              accept  => '127.0.0.1:2049',
              connect => ['my.nfs.host:20490']
            }
          EOM
        end

        let(:title) { 'nfs' }
        let(:params) do
          {
            client: false,
            connect: [2049],
            accept: 20_490,
            trusted_nets: ['any'],
            # Needed to force a recompile in each context
            ocsp: ocsp,
            ocsp_flags: ['NOCERTS'],
          }
        end

        context 'global override' do
          let(:ocsp) { 'https://global.bar.baz' }
          let(:hieradata) { 'defined_type_global_override' }

          it { is_expected.to compile.with_all_deps }
          it {
            is_expected.to create_stunnel__instance(title).with(
              app_pki_ca_dir: '/some/global/ca/dir',
              app_pki_cacert: '/some/global/cacerts.pem',
              app_pki_cert: '/some/global/test.pub',
              app_pki_crl: '/some/global/crl',
              app_pki_dir: '/some/global/dir',
              app_pki_external_source: '/some/global/ext',
              app_pki_key: '/some/global/test.pem',
              compression: 'zlib',
              curve: 'prime256v1',
              delay: true,
              egd: '/some/socket/path',
              engine: 'dynamic',
              engine_ctrl: 'LOAD',
              engine_num: 1,
              exec: '/some/exec',
              execargs: ['arg1', 'arg2'],
              failover: 'prio',
              fips: false,
              firewall: true,
              haveged: false,
              local: '1.2.3.4',
              ocsp: 'https://global.bar.baz',
              ocsp_flags: [ 'NOCERTS' ],
              openssl_cipher_suite: [ 'AES128-SHA256' ],
              options: ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
              output: '/some/log',
              pki: true,
              protocol: 'connect',
              protocol_authentication: 'basic',
              protocol_host: '1.2.3.5:2050',
              protocol_password: 'some_password',
              protocol_username: 'some_user',
              pty: true,
              renegotiation: false,
              reset: false,
              retry: true,
              rnd_bytes: 2048,
              rnd_file: '/some/random',
              rnd_overwrite: false,
              session_cache_size: 20,
              session_cache_timeout: 1000,
              setuid: 'testuid',
              setgid: 'testid',
              sni: 'global.sni.server',
              socket_options: [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
              ssl_version: 'TLSv1',
              stack: 1024,
              stunnel_debug: 'info',
              syslog: true,
              systemd_wantedby: [ 'some.service' ],
              systemd_requiredby: [ 'someother.service' ],
              tcpwrappers: true,
              timeout_busy: 5,
              timeout_close: 10,
              timeout_connect: 15,
              timeout_idle: 20,
              trusted_nets: [ 'any' ],
              verify: 4,
            )
          }

          it {
            is_expected.to create_stunnel__instance('nfs_client').with(
              app_pki_ca_dir: '/some/global/ca/dir',
              app_pki_cacert: '/some/global/cacerts.pem',
              app_pki_cert: '/some/global/test.pub',
              app_pki_crl: '/some/global/crl',
              app_pki_dir: '/some/global/dir',
              app_pki_external_source: '/some/global/ext',
              app_pki_key: '/some/global/test.pem',
              compression: 'zlib',
              curve: 'prime256v1',
              delay: true,
              egd: '/some/socket/path',
              engine: 'dynamic',
              engine_ctrl: 'LOAD',
              engine_num: 1,
              exec: '/some/exec',
              execargs: ['arg1', 'arg2'],
              failover: 'prio',
              fips: false,
              firewall: true,
              haveged: false,
              local: '1.2.3.4',
              ocsp: 'http://foo.bar.baz',
              ocsp_flags: [ 'NOCHAIN' ],
              openssl_cipher_suite: [ 'AES128-SHA256' ],
              options: ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
              output: '/some/log',
              pki: true,
              protocol: 'connect',
              protocol_authentication: 'basic',
              protocol_host: '1.2.3.5:2050',
              protocol_password: 'some_password',
              protocol_username: 'some_user',
              pty: true,
              renegotiation: false,
              reset: false,
              retry: true,
              rnd_bytes: 2048,
              rnd_file: '/some/random',
              rnd_overwrite: false,
              session_cache_size: 20,
              session_cache_timeout: 1000,
              setuid: 'testuid',
              setgid: 'testid',
              sni: 'global.sni.server',
              socket_options: [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
              ssl_version: 'TLSv1',
              stack: 1024,
              stunnel_debug: 'info',
              syslog: true,
              systemd_wantedby: [ 'some.service' ],
              systemd_requiredby: [ 'someother.service' ],
              tcpwrappers: true,
              timeout_busy: 5,
              timeout_close: 10,
              timeout_connect: 15,
              timeout_idle: 20,
              trusted_nets: [ '1.2.3.0/24' ],
              verify: 4,
            )
          }
        end

        context 'specific override' do
          let(:ocsp) { 'https://specific.bar.baz' }
          let(:hieradata) { 'defined_type_specific_override' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_stunnel__instance(title).with_ssl_version('all') }
          it { is_expected.to create_stunnel__instance('nfs_client').with_ssl_version('TLSv1') }
        end
      end
    end
  end
end
