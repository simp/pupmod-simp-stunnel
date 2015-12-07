require 'spec_helper'

describe 'stunnel' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts){ facts }
        it { is_expected.to create_class('stunnel') }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_user('stunnel') }
        it { is_expected.to contain_package('stunnel').that_comes_before('Service[stunnel]') }
        it { is_expected.to contain_concat_fragment('stunnel+0global.conf') }

        context "alternate gid" do
          let(:params) {{ :setgid => 'foo' }}
          it { is_expected.to contain_file('/etc/stunnel').with_group(params[:setgid]) }
        end
      end
    end
  end

end
