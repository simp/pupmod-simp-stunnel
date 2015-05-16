require 'spec_helper'

describe 'stunnel::add' do

  shared_examples_for "a fact set add" do
    context "using iptables" do
      let(:title){ 'nfs' }
      let(:params){{
        :client => false,
        :connect => ['2049'],
        :accept => '20490',
        :client_nets => 'any'
      }}

      it { should compile.with_all_deps }
      it { should create_iptables__add_tcp_stateful_listen("allow_stunnel_#{title}").with({
        :client_nets => 'any',
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
        :client_nets => 'any'
      }}

      it { should compile.with_all_deps }
      it { should create_tcpwrappers__allow("allow_stunnel_#{title}").with_pattern('any') }
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set add"

    let(:facts) {{
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '6',
      :operatingsystemmajrelease => '6',
      :interfaces => 'lo,eth0',
      :ipaddress_lo => '127.0.0.1',
      :ipaddress_eth0 => '1.2.3.4'
    }}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set add"

    let(:facts) {{
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '7',
      :operatingsystemmajrelease => '7',
      :interfaces => 'lo,eth0',
      :ipaddress_lo => '127.0.0.1',
      :ipaddress_eth0 => '1.2.3.4'
    }}
  end
end
