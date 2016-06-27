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
        it { is_expected.to contain_class('haveged') }

        context "alternate gid" do
          let(:params) {{ :setgid => 'foo' }}
          it { is_expected.to contain_file('/etc/stunnel').with_group(params[:setgid]) }
        end

        context 'with use_haveged => false' do
          let(:params) {{:use_haveged => false}}
          it { is_expected.to_not contain_class('haveged') }
        end

        context 'with invalid input' do
          let(:params) {{:use_haveged => 'invalid_input'}}
          it 'with use_haveged as a string' do
            expect {
              is_expected.to compile
            }.to raise_error(RSpec::Expectations::ExpectationNotMetError,/invalid_input" is not a boolean/)
          end
        end
      end
    end
  end

end
