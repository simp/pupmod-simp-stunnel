require 'spec_helper'

describe 'stunnel::connection' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts){ os_facts }

        context "using iptables" do
          let(:title){ 'nfs' }
          let(:params){{
            :client       => false,
            :connect      => [2049],
            :accept       => 20490,
            :trusted_nets => ['any'],
            :firewall     => true
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables__listen__tcp_stateful("allow_stunnel_#{title}").with({
            :trusted_nets => ['any'],
            :dports       => [params[:accept].to_s.split(':')[-1]]
            })
          }
        end

        context "using tcpwrappers" do
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

        context "setting ocsp options" do
          let(:title){ 'nfs' }
          let(:params){{
            :client       => false,
            :connect      => [2049],
            :accept       => 20490,
            :trusted_nets => ['any'],
            :ocsp         => 'http://foo.bar.baz',
            :ocsp_flags   => ['NOCERTS']
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_concat__fragment("stunnel_connection_#{title}").with_content(/NOCERTS/) }
        end

        context "with Hiera overrides" do
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

          context "disabled" do
            let(:ocsp) { 'https://disabled.bar.baz' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_stunnel__connection(title).with_ssl_version(nil) }
            it { is_expected.to create_stunnel__connection("nfs_client").with_ssl_version(nil) }
          end

          context "global" do
            let(:ocsp) { 'https://global.bar.baz' }
            let(:hieradata){ 'defined_type_global_override' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_stunnel__connection(title).with_ssl_version('TLSv1') }
            it { is_expected.to create_stunnel__connection("nfs_client").with_ssl_version('TLSv1') }
          end

          context "specific" do
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
