require 'spec_helper'

describe 'stunnel::connection' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts){ os_facts }

        context 'with default parameters' do
          let(:title){ 'test_tunnel' }
          let(:params){{
            :connect => [2048,2049],
            :accept  => '10.1.2.3:20490',
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_stunnel__instance__reserve_port('20490') }
          it { is_expected.to create_class('stunnel::monolithic') }
          it do
            expected = <<-EOM
[test_tunnel]
connect = 2048
connect = 2049
accept = 10.1.2.3:20490
client = yes
failover = rr
key = /etc/pki/simp_apps/stunnel/x509/private/foo.example.com.pem
cert = /etc/pki/simp_apps/stunnel/x509/public/foo.example.com.pub
CAfile = /etc/pki/simp_apps/stunnel/x509/cacerts/cacerts.pem
CRLpath = /etc/pki/simp_apps/stunnel/x509/crl
ciphers = HIGH:-SSLv2
verify = 2
delay = no
            EOM
            unless facts[:os][:release][:major] < '7'
              expected  += "renegotiation = yes\nreset = yes\n"
            end
            is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(expected)
          end

        end

        context 'using iptables' do
          let(:title){ 'nfs' }
          let(:params){{
            :client       => false,
            :connect      => [2049],
            :accept       => 20490,
            :trusted_nets => ['any'],
            :firewall     => true
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_stunnel__instance__reserve_port('20490') }
          it { is_expected.to create_iptables__listen__tcp_stateful("allow_stunnel_#{title}").with({
            :trusted_nets => ['any'],
            :dports       => [params[:accept].to_s.split(':')[-1]]
            })
          }
        end

        context 'using tcpwrappers' do
          let(:title){ 'nfs' }
          let(:params){{
            :tcpwrappers  => true,
            :client       => false,
            :connect      => [2049],
            :accept       => 20490,
            :trusted_nets => ['any']
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_tcpwrappers__allow("allow_stunnel_#{title}").with_pattern(['any']) }
        end

        context 'setting ocsp options' do
          let(:title){ 'nfs' }
          let(:params){{
            :client       => false,
            :connect      => [2049],
            :accept       => 20490,
            :trusted_nets => ['any'],
            :ocsp         => 'http://foo.bar.baz',
            :ocsp_flags   => ['NOCERTS', 'NOCHAIN']
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(/OCSPFlag = NOCERTS/) }
          it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(/OCSPFlag = NOCHAIN/) }
        end

        context 'with other parameters set' do
          let(:title){ 'test_tunnel' }
          let(:params){{
            :connect                 => [2048,2049],
            :accept                  => '10.1.2.3:20490',
            :curve                   => 'prime256v1',
            :local                   => '1.2.3.4',
            :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG', 'SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS'],
            :protocol                => 'connect',
            :protocol_authentication => 'basic',
            :protocol_host           => '1.2.3.5:2050',
            :protocol_password       => 'some_password',
            :protocol_username       => 'some_user',
            :engine_num              => 1,
            :exec                    => '/some/exec',
            :execargs                => ['arg1', 'arg2'],
            :session_cache_timeout   => 20,
            :session_cache_size      => 1000,
            :sni                     => 'test.sni.server',
            :ssl_version             => 'TLSv1',
            :stack                   => 1024,
            :timeout_busy            => 5,
            :timeout_close           => 10,
            :timeout_connect         => 15,
            :timeout_idle            => 20
          }}

          it { is_expected.to compile.with_all_deps }

          if os_facts[:os][:release][:major] < '7'
            it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(/session = 20/) }
          else
            [ /sni = test.sni.server/,
              /sessionCacheTimeout = 20/,
              /sessionCacheSize = 1000/,
              /renegotiation = yes/,
              /reset = yes/
            ].each do |exp_regex|
              it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(exp_regex) }
            end
          end

          [ /curve = prime256v1/,
            /sslVersion = TLSv1/,
            /options = SSL_OP_NETSCAPE_CHALLENGE_BUG/,
            /options = SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS/,
            /local = 1.2.3.4/,
            /protocol = connect/,
            /protocolAuthentication = basic/,
            /protocolHost = 1\.2\.3\.5:2050/,
            /protocolPassword = some_password/,
            /protocolUsername = some_user/,
            /engineNum = 1/,
            /exec = \/some\/exec/,
            /execargs = arg1 arg2/,
            /pty = no/,
            /retry = no/,
            /stack = 1024/,
            /TIMEOUTbusy = 5/,
            /TIMEOUTclose = 10/,
            /TIMEOUTconnect = 15/,
            /TIMEOUTidle = 20/
          ].each do |exp_regex|
            it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(exp_regex) }
          end
        end

        context 'with Hiera overrides' do
          let(:pre_condition) { <<-EOM
            stunnel::connection{ 'nfs_client':
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
            it { is_expected.to create_stunnel__connection(title).with(
              :app_pki_cacert          => '/some/global/cacerts.pem',
              :app_pki_cert            => '/some/global/test.pub',
              :app_pki_crl             => '/some/global/crl',
              :app_pki_key             => '/some/global/test.pem',
              :curve                   => 'prime256v1',
              :delay                   => true,
              :engine_num              => 1,
              :exec                    => '/some/exec',
              :execargs                => ['arg1', 'arg2'],
              :failover                => 'prio',
              :firewall                => true,
              :local                   => '1.2.3.4',
              :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
              :ocsp                    => 'https://global.bar.baz',
              :ocsp_flags              => [ 'NOCERTS' ],
              :openssl_cipher_suite    => [ 'AES128-SHA256' ],
              :protocol                => 'connect',
              :protocol_authentication => 'basic',
              :protocol_host           => '1.2.3.5:2050',
              :protocol_password       => 'some_password',
              :protocol_username       => 'some_user',
              :pty                     => true,
              :renegotiation           => false,
              :reset                   => false,
              :retry                   => true,
              :session_cache_size      => 20,
              :session_cache_timeout   => 1000,
              :sni                     => 'global.sni.server',
              :ssl_version             => 'TLSv1',
              :stack                   => 1024,
              :tcpwrappers             => true,
              :timeout_busy            => 5,
              :timeout_close           => 10,
              :timeout_connect         => 15,
              :timeout_idle            => 20,
              :trusted_nets            => [ 'any' ],
              :verify                  => 4,
            ) }

            it { is_expected.to create_stunnel__connection("nfs_client").with(
              :app_pki_cacert          => '/some/global/cacerts.pem',
              :app_pki_cert            => '/some/global/test.pub',
              :app_pki_crl             => '/some/global/crl',
              :app_pki_key             => '/some/global/test.pem',
              :curve                   => 'prime256v1',
              :delay                   => true,
              :engine_num              => 1,
              :exec                    => '/some/exec',
              :execargs                => ['arg1', 'arg2'],
              :failover                => 'prio',
              :firewall                => true,
              :local                   => '1.2.3.4',
              :ocsp                    => 'http://foo.bar.baz',
              :ocsp_flags              => [ 'NOCHAIN' ],
              :openssl_cipher_suite    => [ 'AES128-SHA256' ],
              :options                 => ['SSL_OP_NETSCAPE_CHALLENGE_BUG' ],
              :protocol                => 'connect',
              :protocol_authentication => 'basic',
              :protocol_host           => '1.2.3.5:2050',
              :protocol_password       => 'some_password',
              :protocol_username       => 'some_user',
              :pty                     => true,
              :renegotiation           => false,
              :reset                   => false,
              :retry                   => true,
              :session_cache_size      => 20,
              :session_cache_timeout   => 1000,
              :sni                     => 'global.sni.server',
              :ssl_version             => 'TLSv1',
              :stack                   => 1024,
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
            it { is_expected.to create_stunnel__connection(title).with_ssl_version('all') }
            it { is_expected.to create_stunnel__connection("nfs_client").with_ssl_version('TLSv1') }
          end
        end
      end
    end
  end
end
