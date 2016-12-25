require 'spec_helper'

describe 'stunnel::connection' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts){ facts }

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
            :libwrap      => true,
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
      end
    end
  end
end
