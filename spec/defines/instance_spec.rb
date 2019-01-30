require 'spec_helper'

describe 'stunnel::instance' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:title) { 'nfs' }
      let(:facts) {
        os_facts.merge(
          selinux_current_mode: 'enabled',
          selinux_enforced: true
        )
      }

      context 'with default parameters' do
        let(:params) {{
          connect: [2049],
          accept:  '10.1.2.3:20490',
        }}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_stunnel__instance__reserve_port('20490') }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_stunnel_nfs') }
        it { is_expected.to_not create_tcpwrappers__allow('allow_stunnel_nfs') }
        it { is_expected.to_not create_pki__copy('stunnel_nfs') }
        it { is_expected.to_not create_file('/var/stunnel_nfs') }
      end

      context 'with firewall, tcpwrappers, pki, fips true' do
        let(:params) {{
          client:       false,
          connect:      [2049],
          accept:       20490,
          trusted_nets: ['any'],
          firewall:     true,
          tcpwrappers:  true,
          pki:          true,
          fips:         true
        }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/stunnel') }
        # Some differences in el6 vs el7+ content
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/nonchroot-systemd.txt') }
          let(:stunnel_conf) { File.read('spec/expected/instance/non_chroot_el7_stunnel.conf.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf') \
            .with_content(stunnel_conf) }
          it { is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service') \
            .with_content(service_file)}
        else
          let(:service_file) { File.read('spec/expected/instance/nonchroot-init.txt') }
          let(:stunnel_conf) { File.read('spec/expected/instance/non_chroot_el6_stunnel.conf.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf') \
            .with_content(stunnel_conf) }
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_managed_by_puppet_nfs') \
            .with_content(service_file)}
        end
        it { is_expected.to create_iptables__listen__tcp_stateful('allow_stunnel_nfs').with(
            trusted_nets: ['any'],
            dports:       [params[:accept].to_s.split(':')[-1]]
          )
        }
        it { is_expected.to create_tcpwrappers__allow('allow_stunnel_nfs') \
          .with_pattern(['any']) }
        it { is_expected.to create_pki__copy('stunnel_nfs') }
        it { is_expected.to contain_class('stunnel::install') }
      end

      context 'when chrooted and pki true' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
          pki:     true
        }}
        let(:facts) {
          os_facts.merge(
            selinux_current_mode: 'disabled',
            selinux_enforced: false
          )
        }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_nfs') }
        it { is_expected.to create_file('/var/stunnel_nfs/etc/pki/cacerts') \
          .that_requires('Pki::Copy[stunnel_nfs]') }
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/chroot-systemd.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf') \
            .with_content(/.*chroot = \/var\/stunnel_nfs.*/)}
          it { is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service') \
            .with_content(service_file) }
        else
          let(:service_file) { File.read('spec/expected/instance/chroot-init.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_nfs.conf') \
            .with_content(/.*chroot = \/var\/stunnel_nfs.*/)}
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_managed_by_puppet_nfs') \
            .with_content(service_file) }
        end
      end

      # This behavior is not recommended or supported
      context 'when chrooted and selinux enabled' do
        let(:title) { 'sel' }
        let(:params) {{
          connect: [2049],
          accept:  20490,
          pki:     true,
          chroot:  '/var/stunnel_sel'
        }}
        let(:facts) {
          os_facts.merge(
            selinux_current_mode: 'enforcing',
            selinux_enforced: true
          )
        }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_sel') }
        it { is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts') }
        it { is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts') \
          .that_requires('Pki::Copy[stunnel_sel]') }
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/chroot-sel-systemd.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_sel.conf') \
            .with_content(/.*chroot = \/var\/stunnel_sel.*/)}
          it { is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_sel.service') \
            .with_content(service_file) }
        else
          let(:service_file) { File.read('spec/expected/instance/chroot-sel-init.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_managed_by_puppet_sel.conf') \
            .with_content(/.*chroot = \/var\/stunnel_sel.*/)}
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_managed_by_puppet_sel') \
            .with_content(service_file) }
        end
      end

      # Make sure there are no resource issues when including legacy stunnel
      context 'when including (legacy) stunnel' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:pre_condition) { <<-EOF
            stunnel::connection { 'test':
              connect => [1234],
              accept  => 1234
            }
          EOF
        }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel') }
        it { is_expected.to contain_class('stunnel::config') }
        it { is_expected.to contain_class('stunnel::service') }
        it { is_expected.to contain_class('stunnel::install') }

        # Ensure that conflicting connection and instances fail to compile
        context 'with conflicting instances and connections' do
          let(:pre_condition) { <<-EOF
              stunnel::connection { 'conflicting_test':
                connect => [1234],
                accept  => #{params[:accept]}
              }
            EOF
          }

          it {
            is_expected.to compile.and_raise_error(
              /Duplicate.*\s+Stunnel::Instance::Reserve_port\[#{params[:accept]}\]/
            )
          }
        end
      end

      context 'when selinux is disabled' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:facts) { os_facts.merge(selinux_enforced: false) }

        if os_facts[:os][:release][:major].to_i >= 7
          it { is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service') \
            .without_content(/system_u:object_r:stunnel_var_run_t/)}
        else
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_managed_by_puppet_nfs') \
            .without_content(/^\s+mkdir -p system_u:object_r:stunnel_var_run_t/)}
        end
      end

      context 'with systemd dependencies' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
          systemd_wantedby: ['nfs.service'],
          systemd_requiredby: ['nfs-server.service']
        }}

        if os_facts[:os][:release][:major].to_i >= 7
          it { is_expected.to create_file('/etc/systemd/system/stunnel_managed_by_puppet_nfs.service') \
            .with_content(/WantedBy=nfs.service/) \
            .with_content(/RequiredBy=nfs-server.service/)
          }
        end
      end

      context 'on an unsupported OS' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:facts) { os_facts.merge(init_systems: ['rc']) }
        it { is_expected.to compile.and_raise_error(/Init systems.*not supported/) }
      end

      context 'with other parameters set' do
        let(:title){ 'test_tunnel' }
        let(:conf_file){ '/etc/stunnel/stunnel_managed_by_puppet_test_tunnel.conf' }
        let(:params){{
          :connect                 => [2048,2049],
          :accept                  => '10.1.2.3:20490',
          :compression             => 'zlib',
          :curve                   => 'prime256v1',
          :egd                     => '/some/socket/path',
          :engine_ctrl             => 'LOAD',
          :engine_num              => 1,
          :exec                    => '/some/exec',
          :execargs                => ['arg1', 'arg2'],
          :local                   => '1.2.3.4',
          :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG', 'SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS'],
          :output                  => '/some/log',
          :protocol                => 'connect',
          :protocol_authentication => 'basic',
          :protocol_host           => '1.2.3.5:2050',
          :protocol_password       => 'some_password',
          :protocol_username       => 'some_user',
          :rnd_bytes               => 2048,
          :rnd_file                => '/some/random',
          :session_cache_timeout   => 20,
          :session_cache_size      => 1000,
          :sni                     => 'test.sni.server',
          :socket_options          => [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
          :ssl_version             => 'TLSv1',
          :stack                   => 1024,
          :timeout_busy            => 5,
          :timeout_close           => 10,
          :timeout_connect         => 15,
          :timeout_idle            => 20
        }}

        it { is_expected.to compile.with_all_deps }

        if os_facts[:os][:release][:major] < '7'
          it { is_expected.to create_file(conf_file).with_content(/session = 20/) }
        else
          [ /sni = test.sni.server/,
            /sessionCacheTimeout = 20/,
            /sessionCacheSize = 1000/,
            /renegotiation = yes/,
            /reset = yes/
          ].each do |exp_regex|
            it { is_expected.to create_file(conf_file).with_content(exp_regex) }
          end
        end

        [ /compression = zlib/,
          /curve = prime256v1/,
          /EGD = \/some\/socket\/path/,
          /engineCtrl = LOAD/,
          /engineNum = 1/,
          /exec = \/some\/exec/,
          /execargs = arg1 arg2/,
          /local = 1.2.3.4/,
          /options = SSL_OP_NETSCAPE_CHALLENGE_BUG/,
          /options = SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS/,
          /output = \/some\/log/,
          /protocol = connect/,
          /protocolAuthentication = basic/,
          /protocolHost = 1\.2\.3\.5:2050/,
          /protocolPassword = some_password/,
          /protocolUsername = some_user/,
          /pty = no/,
          /retry = no/,
          /RNDbytes = 2048/,
          /RNDfile = \/some\/random/,
# SIMP-6060
#          /RNDoverwrite = false/,
          /socket = l:SO_LINGER=1:60/,
          /socket = r:TCP_NODELAY=1/,
          /sslVersion = TLSv1/,
          /stack = 1024/,
          /TIMEOUTbusy = 5/,
          /TIMEOUTclose = 10/,
          /TIMEOUTconnect = 15/,
          /TIMEOUTidle = 20/
        ].each do |exp_regex|
          it { is_expected.to create_file(conf_file).with_content(exp_regex) }
        end
      end

      context 'with Hiera overrides' do
        let(:pre_condition) { <<-EOM
          stunnel::instance{ 'nfs_client':
            accept  => '127.0.0.1:2049',
            connect => ['my.nfs.host:20490']
          }
          EOM
        }

        let(:title){ 'nfs' }
        let(:params){{
          :client       => false,
          :connect      => [2049],
          :accept       => 20490,
          :trusted_nets => ['any'],
          # Needed to force a recompile in each context
          :ocsp         => ocsp,
          :ocsp_flags   => ['NOCERTS']
        }}

        context 'global override' do
          let(:ocsp) { 'https://global.bar.baz' }
          let(:hieradata){ 'defined_type_global_override' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_stunnel__instance(title).with(
            :app_pki_ca_dir          => '/some/global/ca/dir',
            :app_pki_cacert          => '/some/global/cacerts.pem',
            :app_pki_cert            => '/some/global/test.pub',
            :app_pki_crl             => '/some/global/crl',
            :app_pki_dir             => '/some/global/dir',
            :app_pki_external_source => '/some/global/ext',
            :app_pki_key             => '/some/global/test.pem',
            :compression             => 'zlib',
            :curve                   => 'prime256v1',
            :delay                   => true,
            :egd                     => '/some/socket/path',
            :engine                  => 'dynamic',
            :engine_ctrl             => 'LOAD',
            :engine_num              => 1,
            :exec                    => '/some/exec',
            :execargs                => ['arg1', 'arg2'],
            :failover                => 'prio',
            :fips                    => false,
            :firewall                => true,
            :haveged                 => false,
            :local                   => '1.2.3.4',
            :ocsp                    => 'https://global.bar.baz',
            :ocsp_flags              => [ 'NOCERTS' ],
            :openssl_cipher_suite    => [ 'AES128-SHA256' ],
            :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
            :output                  => '/some/log',
            :pki                     => true,
            :protocol                => 'connect',
            :protocol_authentication => 'basic',
            :protocol_host           => '1.2.3.5:2050',
            :protocol_password       => 'some_password',
            :protocol_username       => 'some_user',
            :pty                     => true,
            :renegotiation           => false,
            :reset                   => false,
            :retry                   => true,
            :rnd_bytes               => 2048,
            :rnd_file                => '/some/random',
            :rnd_overwrite           => true,
            :session_cache_size      => 20,
            :session_cache_timeout   => 1000,
            :setuid                  => 'testuid',
            :setgid                  => 'testid',
            :sni                     => 'global.sni.server',
            :socket_options          => [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
            :ssl_version             => 'TLSv1',
            :stack                   => 1024,
            :stunnel_debug           => 'info',
            :syslog                  => true,
            :systemd_wantedby        => [ 'some.service' ],
            :systemd_requiredby      => [ 'someother.service' ],
            :tcpwrappers             => true,
            :timeout_busy            => 5,
            :timeout_close           => 10,
            :timeout_connect         => 15,
            :timeout_idle            => 20,
            :trusted_nets            => [ 'any' ],
            :verify                  => 4,
          ) }

          it { is_expected.to create_stunnel__instance('nfs_client').with(
            :app_pki_ca_dir          => '/some/global/ca/dir',
            :app_pki_cacert          => '/some/global/cacerts.pem',
            :app_pki_cert            => '/some/global/test.pub',
            :app_pki_crl             => '/some/global/crl',
            :app_pki_dir             => '/some/global/dir',
            :app_pki_external_source => '/some/global/ext',
            :app_pki_key             => '/some/global/test.pem',
            :compression             => 'zlib',
            :curve                   => 'prime256v1',
            :delay                   => true,
            :egd                     => '/some/socket/path',
            :engine                  => 'dynamic',
            :engine_ctrl             => 'LOAD',
            :engine_num              => 1,
            :exec                    => '/some/exec',
            :execargs                => ['arg1', 'arg2'],
            :failover                => 'prio',
            :fips                    => false,
            :firewall                => true,
            :haveged                 => false,
            :local                   => '1.2.3.4',
            :ocsp                    => 'http://foo.bar.baz',
            :ocsp_flags              => [ 'NOCHAIN' ],
            :openssl_cipher_suite    => [ 'AES128-SHA256' ],
            :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
            :output                  => '/some/log',
            :pki                     => true,
            :protocol                => 'connect',
            :protocol_authentication => 'basic',
            :protocol_host           => '1.2.3.5:2050',
            :protocol_password       => 'some_password',
            :protocol_username       => 'some_user',
            :pty                     => true,
            :renegotiation           => false,
            :reset                   => false,
            :retry                   => true,
            :rnd_bytes               => 2048,
            :rnd_file                => '/some/random',
            :rnd_overwrite           => true,
            :session_cache_size      => 20,
            :session_cache_timeout   => 1000,
            :setuid                  => 'testuid',
            :setgid                  => 'testid',
            :sni                     => 'global.sni.server',
            :socket_options          => [ 'l:SO_LINGER=1:60', 'r:TCP_NODELAY=1' ],
            :ssl_version             => 'TLSv1',
            :stack                   => 1024,
            :stunnel_debug           => 'info',
            :syslog                  => true,
            :systemd_wantedby        => [ 'some.service' ],
            :systemd_requiredby      => [ 'someother.service' ],
            :tcpwrappers             => true,
            :timeout_busy            => 5,
            :timeout_close           => 10,
            :timeout_connect         => 15,
            :timeout_idle            => 20,
            :trusted_nets            => [ '1.2.3.0/24' ],
            :verify                  => 4,
          ) }
        end

        context 'specific override' do
          let(:ocsp) { 'https://specific.bar.baz' }
          let(:hieradata){ 'defined_type_specific_override' }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_stunnel__instance(title).with_ssl_version('all') }
          it { is_expected.to create_stunnel__instance('nfs_client').with_ssl_version('TLSv1') }
        end
      end
    end
  end
end
