require 'spec_helper'

$el7_non_chroot = <<EOF
setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel_nfs.pid
engine = auto
fips = yes
[nfs]
connect = 2049
accept = 20490
client = no
failover = rr
key = /etc/pki/simp_apps/stunnel_nfs/x509/private/foo.example.com.pem
cert = /etc/pki/simp_apps/stunnel_nfs/x509/public/foo.example.com.pub
CAfile = /etc/pki/simp_apps/stunnel_nfs/x509/cacerts/cacerts.pem
CRLpath = /etc/pki/simp_apps/stunnel_nfs/x509/crl
ciphers = HIGH:-SSLv2
verify = 2
delay = no
retry = no
renegotiation = yes
reset = yes
EOF

$el6_non_chroot = <<EOF
setgid = stunnel
setuid = stunnel
debug = err
syslog = no
pid = /var/run/stunnel/stunnel_nfs.pid
engine = auto
[nfs]
connect = 2049
accept = 20490
client = no
failover = rr
key = /etc/pki/simp_apps/stunnel_nfs/x509/private/foo.example.com.pem
cert = /etc/pki/simp_apps/stunnel_nfs/x509/public/foo.example.com.pub
CAfile = /etc/pki/simp_apps/stunnel_nfs/x509/cacerts/cacerts.pem
CRLpath = /etc/pki/simp_apps/stunnel_nfs/x509/crl
ciphers = HIGH:-SSLv2
verify = 2
delay = no
retry = no
EOF

describe 'stunnel::instance' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) { facts }

        context 'with default parameters' do
          let(:title) { 'nfs' }
          let(:params) {{
            connect: [2049],
            accept:  20490,
          }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('stunnel::install') }
          it { is_expected.to_not create_iptables__listen__tcp_stateful("allow_stunnel_#{title}") }
          it { is_expected.to_not create_tcpwrappers__allow("allow_stunnel_#{title}") }
          it { is_expected.to_not create_pki__copy("stunnel_#{title}") }
          it { is_expected.to_not create_file("/var/stunnel_#{title}") }
        end

        context 'with firewall, tcpwrappers, pki, fips true' do
          let(:title) { 'nfs' }
          let(:params) {{
            client:       false,
            connect:      [2049],
            accept:       20490,
            trusted_nets: ['any'],
            firewall:     true,
            tcpwrappers:  true,
            pki:          true,
            fips:         true
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/stunnel') }
          # Some differences in el6 vs el7+ content
          if facts[:osfamily] == 'RedHat'
            if facts[:os][:release][:major].to_i >= 7
              it { is_expected.to contain_file("/etc/stunnel/stunnel_#{title}.conf") \
                .with_content($el7_non_chroot) }
              it { is_expected.to create_file("/etc/systemd/system/stunnel_#{title}.service") \
                .with_content(/.*ExecStart=\/usr\/bin\/stunnel \/etc\/stunnel\/stunnel_#{title}.conf.*/)}
            else
              it { is_expected.to contain_file("/etc/stunnel/stunnel_#{title}.conf") \
                .with_content($el6_non_chroot) }
              it { is_expected.to create_file("/etc/rc.d/init.d/stunnel_#{title}") \
                .with_content(/.*conf=\/etc\/stunnel\/stunnel_#{title}.conf.*/)}
            end
          end
          it { is_expected.to create_iptables__listen__tcp_stateful("allow_stunnel_#{title}") \
            .with({
            trusted_nets: ['any'],
            dports:       [params[:accept].to_s.split(':')[-1]]
            })
          }
          it { is_expected.to create_tcpwrappers__allow("allow_stunnel_#{title}") \
            .with_pattern(['any']) }
          it { is_expected.to create_pki__copy("stunnel_#{title}") }
          it { is_expected.to contain_class('stunnel::install') }
        end

        context 'when chrooted and pki true' do
          let(:title) { 'nfs' }
          let(:params) {{
            connect: [2049],
            accept:  20490,
            pki:     true
          }}
          let(:facts) {facts.merge(selinux_current_mode: 'disabled')}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('stunnel::install') }
          it { is_expected.to create_file("/var/stunnel_#{title}") }
          it { is_expected.to create_file("/var/stunnel_#{title}/etc/pki/cacerts") \
            .that_requires("Pki::Copy[stunnel_#{title}]") }
          if facts[:osfamily] == 'RedHat'
            if facts[:os][:release][:major].to_i >= 7
              it { is_expected.to contain_file("/etc/stunnel/stunnel_#{title}.conf") \
                .with_content(/.*chroot = \/var\/stunnel_#{title}.*/)}
              it { is_expected.to create_file("/etc/systemd/system/stunnel_#{title}.service") \
                .with_content(/.*ExecStart=\/usr\/bin\/stunnel \/etc\/stunnel\/stunnel_#{title}.conf.*/)}
            else
              it { is_expected.to contain_file("/etc/stunnel/stunnel_#{title}.conf") \
                .with_content(/.*chroot = \/var\/stunnel_#{title}.*/)}
              it { is_expected.to create_file("/etc/rc.d/init.d/stunnel_#{title}") \
                .with_content(/.*conf=\/etc\/stunnel\/stunnel_#{title}.conf.*/)}
            end
          end
        end

        # Make sure there are no resource issues when including legacy stunnel
        context 'when including (legacy) stunnel' do
          let(:title) { 'nfs' }
          let(:params) {{
            connect: [2049],
            accept:  20490,
          }}
          let(:pre_condition) { 'include stunnel' }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_class('stunnel') }
          it { is_expected.to contain_class('stunnel::config') }
          it { is_expected.to contain_class('stunnel::service') }
          it { is_expected.to contain_class('stunnel::install') }
        end

        context 'when selinux is disabled' do
          let(:title) { 'nfs' }
          let(:params) {{
            connect: [2049],
            accept:  20490,
          }}
          let(:facts) { facts.merge(selinux_enforced: false) }

          if facts[:os][:release][:major].to_i >= 7
            it { is_expected.to create_file("/etc/systemd/system/stunnel_#{title}.service") \
              .without_content(/system_u:object_r:stunnel_var_run_t/)}
          else
            it { is_expected.to create_file("/etc/rc.d/init.d/stunnel_#{title}") \
              .without_content(/^\s+mkdir -p system_u:object_r:stunnel_var_run_t/)}
          end
        end

        context 'on an unsupported OS' do
          let(:title) { 'nfs' }
          let(:params) {{
            connect: [2049],
            accept:  20490,
          }}
          let(:facts) { facts.merge(init_systems: ['rc']) }
          it { is_expected.to compile.and_raise_error(/Init systems.*not supported/) }
        end

      end
    end
  end
end
