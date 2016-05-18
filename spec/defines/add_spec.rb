require 'spec_helper'

describe 'stunnel::add' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts){ facts }

        context "using iptables" do
          let(:title){ 'nfs' }
          let(:params){{
            :client => false,
            :connect => ['2049'],
            :accept => '20490',
            :client_nets => ['any']
          }}

          it { should compile.with_all_deps }
          it { should create_iptables__add_tcp_stateful_listen("allow_stunnel_#{title}").with({
            :client_nets => ['any'],
            :dports => params[:accept].split(':')[-1]
            })
          }
        end

        context "using tcpwrappers" do
          let(:title){ 'nfs' }
          let(:params){{
            :libwrap => true,
            :client => false,
            :connect => ['2049'],
            :accept => '20490',
            :client_nets => ['any']
          }}

          it { should compile.with_all_deps }
          it { should create_tcpwrappers__allow("allow_stunnel_#{title}").with_pattern(['any']) }
        end
      end
    end
  end
end
