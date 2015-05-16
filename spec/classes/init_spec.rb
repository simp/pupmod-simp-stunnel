require 'spec_helper'

describe 'stunnel' do

  base_facts = {
    "RHEL 6" => {
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '6',
      :operatingsystemmajrelease => '6'
    },
    "RHEL 7" => {
      :fqdn => 'spec.test',
      :uid_min => '500',
      :grub_version => '0.97',
      :hardwaremodel => 'x86_64',
      :operatingsystem => 'RedHat',
      :lsbmajdistrelease => '7',
      :operatingsystemmajrelease => '7'
    }
  }

  shared_examples_for "a fact set init" do
    it { should create_class('stunnel') }
    it { should compile.with_all_deps }
    it { should contain_user('stunnel') }
    it { should contain_package('stunnel').that_comes_before('Service[stunnel]') }
    it { should contain_concat_fragment('stunnel+0global.conf') }

    context "alternate gid" do
      let(:params) {{ :setgid => 'foo' }}
      it { should contain_file('/etc/stunnel').with_group(params[:setgid]) }
    end
  end

  describe "RHEL 6" do
    it_behaves_like "a fact set init"
    let(:facts) {base_facts['RHEL 6']}
  end

  describe "RHEL 7" do
    it_behaves_like "a fact set init"
    let(:facts) {base_facts['RHEL 7']}
  end
end
