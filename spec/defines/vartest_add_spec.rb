require 'spec_helper'

def variable_test(title,key,val,opts={})
  opts[:key_str] ||= key.to_s
  opts[:val_str] ||= val.to_s
  opts[:params] ||= {}
  opts[:err] ||= nil
  opts[:errmsg] ||= /.*/
  opts[:content] ||= /^\s*#{opts[:key_str]} = #{opts[:val_str]}\n/

  context "with #{key} => #{val}" do

    let(:title) { title }
    let(:params) { {key => val}.merge(opts[:params]) }

    if opts[:err]
      it do
        expect { should contain_concat__fragment("stunnel_connection_#{title}") }.to
          raise_error(opts[:err],opts[:errmsg])
      end
    else

      it do
        should contain_concat__fragment("stunnel_connection_#{title}").with_content(opts[:content])
      end
    end
  end
end

describe 'stunnel::connection' do

  shared_examples_for "a fact set vartest add" do
    variable_test(
      'nfs',
      :connect,
      ['127.0.0.1:2049'],
      { :params => {
          :client => false,
          :accept => 20490
        },
        :val_str => '127.0.0.1:2049'
      })

    variable_test(
      'nfs',
      :failover,
      'prio',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        }
      })

    variable_test(
      'nfs',
      :app_pki_key,
      '/foo/bar/baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'key'
      })

    variable_test(
      'nfs',
      :app_pki_cert,
      '/foo/bar/baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'cert'
      })

    variable_test(
      'nfs',
      :app_pki_cacert,
      '/foo/bar/baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'CAfile'
      })

    variable_test(
      'nfs',
      :app_pki_crl,
      '/foo/bar/baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'CRLpath'
      })

    variable_test(
      'nfs',
      :openssl_cipher_suite,
      ['HIGH','FOO'],
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'ciphers',
        :val_str => 'HIGH:FOO'
      })

    variable_test(
      'nfs',
      :ssl_version,
      'TLSv1',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'sslVersion'
      })

    variable_test(
      'nfs',
      :options,
      ['opt_one','opt_two'],
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :content => /\s*options = opt_one\n\s*options = opt_two/
      })

    variable_test(
      'nfs',
      :verify,
      2,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        }
      })

    variable_test(
      'nfs',
      :ocsp,
      'http://ocsp.bar.baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'OCSP'
      })

    variable_test(
      'nfs',
      :ocsp_flags,
      ['NOCERTS','NOINTERN'],
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :ocsp => 'http://ocsp.bar.baz'
        },
        :content => /\s*OCSPFlag = NOCERTS\nOCSPFlag = NOINTERN/
      })

    variable_test(
      'nfs',
      :local,
      '1.2.3.4',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        }
      })

    variable_test(
      'nfs',
      :protocol,
      'connect',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        }
      })

    variable_test(
      'nfs',
      :protocol_authentication,
      'NTLM',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :protocol => 'connect'
        },
        :key_str => 'protocolAuthentication'
      })

    variable_test(
      'nfs',
      :protocol_host,
      'host.bar.baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :protocol => 'connect'
        },
        :key_str => 'protocolHost'
      })

    variable_test(
      'nfs',
      :protocol_password,
      'password',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :protocol => 'connect'
        },
        :key_str => 'protocolPassword'
      })

    variable_test(
      'nfs',
      :protocol_username,
      'username',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :protocol => 'connect'
        },
        :key_str => 'protocolUsername'
      })

    variable_test(
      'nfs',
      :delay,
      true,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :val_str => 'yes'
      })

    variable_test(
      'nfs',
      :app_pki_key,
      '/foo/bar/baz',
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'key'
      })

    variable_test(
      'nfs',
      :pty,
      true,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :exec => '/bin/foo',
        },
        :val_str => 'yes'
      })

    variable_test(
      'nfs',
      :retry,
      true,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490,
          :exec => '/bin/foo',
      },
      :val_str => 'yes'
    })

    variable_test(
      'nfs',
      :stack,
      12345,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        }
      })

    variable_test(
      'nfs',
      :timeout_busy,
      12345,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'TIMEOUTbusy'
      })

    variable_test(
      'nfs',
      :timeout_close,
      12345,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'TIMEOUTclose'
      })

    variable_test(
      'nfs',
      :timeout_connect,
      12345,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'TIMEOUTconnect'
      })

    variable_test(
      'nfs',
      :timeout_idle,
      12345,
      { :params => {
          :connect => [2049],
          :client => false,
          :accept => 20490
        },
        :key_str => 'TIMEOUTidle'
      })

    context "specific client nets" do
      let(:title){ 'nfs' }
      let(:params){{
        :trusted_nets => ['1.2.3.4','5.4.3.2/20'],
        :connect => [2049],
        :client => false,
        :accept => 20490
      }}

        it { should compile.with_all_deps }
     end
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts){ facts }
        it_behaves_like "a fact set vartest add"

        if facts[:operatingsystemmajrelease] == '6'
          variable_test(
            'nfs',
            :session_cache_timeout,
            12345,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :key_str => 'session'
          })
        elsif facts[:operatingsystemmajrelease] == '7'
          ['foo','foo:bar'].each do |sni_opts|
            variable_test(
              'nfs',
              :sni,
              'foo:bar',
              { :params => {
                  :connect => [2049],
                  :client => false,
                  :accept => 20490
              }
            })
          end

          variable_test(
            'nfs',
            :curve,
            'longer_string_name',
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            }
          })

          variable_test(
            'nfs',
            :engine_num,
            5,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :key_str => 'engineNum'
          })

          variable_test(
            'nfs',
            :session_cache_size,
            12345,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :key_str => 'sessionCacheSize'
          })

          variable_test(
            'nfs',
            :session_cache_timeout,
            12345,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :key_str => 'sessionCacheTimeout'
          })

          variable_test(
            'nfs',
            :reset,
            true,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :val_str => 'yes'
          })

          variable_test(
            'nfs',
            :renegotiation,
            true,
            { :params => {
                :connect => [2049],
                :client => false,
                :accept => 20490
            },
            :val_str => 'yes'
          })
        end
      end
    end
  end
end
