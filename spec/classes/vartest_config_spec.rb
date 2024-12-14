require 'spec_helper'

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

def variable_test(key, val, opts = {})
  opts[:key_str] ||= key.to_s
  opts[:val_str] ||= val.to_s
  opts[:params] ||= {}
  opts[:err] ||= nil
  opts[:errmsg] ||= %r{.*}

  context "with #{key} => #{val}" do
    let(:params) { { key => val }.merge(opts[:params]) }

    if opts[:err]
      it do
        expect { is_expected.to contain_user('stunnel') }.to raise_error(opts[:err], opts[:errmsg])
      end
    else

      it do
        is_expected.to contain_concat__fragment('0_stunnel_global').with({
                                                                           'content' => %r{^\s*#{opts[:key_str]} = #{opts[:val_str]}\n}
                                                                         })
      end
    end
  end
end

describe 'stunnel::config' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          mock_selinux_false_facts(os_facts)
        end

        it { is_expected.to compile.with_all_deps }

        it do
          is_expected.to contain_concat__fragment('0_stunnel_global').with({
                                                                             'content' => %r{.*chroot = /var/stunnel\nsetgid = stunnel\nsetuid = stunnel\ndebug = err\n.*}
                                                                           })
        end

        variable_test(:compression, 'zlib')
        variable_test(:chroot, '/foo/bar')
        variable_test(:setuid, 'foo')
        variable_test(:setgid, 'bar')
        variable_test(:stunnel_debug, 'warn', { key_str: 'debug' })
        variable_test(:syslog, false, { val_str: 'no' })
        variable_test(:compression, 'rle')
        variable_test(:egd, '/foo/bar', { key_str: 'EGD' })
        variable_test(:engine, 'TEST')
        variable_test(:engine_ctrl, 'TEST_CTRL', { key_str: 'engineCtrl' })
        variable_test(:output, '/foo.bar.out')
        variable_test(:rnd_bytes, 20, { key_str: 'RNDbytes' })
        variable_test(:rnd_overwrite, false, { key_str: 'RNDoverwrite', val_str: 'no' })
        variable_test(:socket_options, ['a:foo=bar'], { key_str: 'socket', val_str: 'a:foo=bar' })
        variable_test(:socket_options, 'a:foo=bar', { err: Puppet::Error, errmsg: %r{expects an Array value, got String} })
      end
    end
  end
end
