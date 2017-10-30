require 'spec_helper'

$el7_non_chroot = <<EOF
setgid = stunnel
setuid = stunnel
debug = err
syslog = no
foreground = yes
pid =
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
foreground = no
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
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:title) { 'nfs' }
      let(:facts) {
        os_facts.merge(
          selinux_current_mode: 'enabled',
          selinux_enforced: true
        )
      }

      context 'with default parameters' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to_not create_iptables__listen__tcp_stateful('allow_stunnel_nfs') }
        it { is_expected.to_not create_tcpwrappers__allow('allow_stunnel_nfs') }
        it { is_expected.to_not create_pki__copy('stunnel_nfs') }
        it { is_expected.to_not create_file('/var/stunnel_nfs') }
      end

      context 'with firewall, tcpwrappers, pki, fips true' do
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
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/nonchroot-systemd.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_nfs.conf') \
            .with_content($el7_non_chroot) }
          it { is_expected.to create_file('/etc/systemd/system/stunnel_nfs.service') \
            .with_content(service_file)}
        else
          let(:service_file) { File.read('spec/expected/instance/nonchroot-init.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_nfs.conf') \
            .with_content($el6_non_chroot) }
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_nfs') \
            .with_content(service_file)}
        end
        it { is_expected.to create_iptables__listen__tcp_stateful('allow_stunnel_nfs').with(
            trusted_nets: ['any'],
            dports:       [params[:accept].to_s.split(':')[-1]]
          )
        }
        it { is_expected.to create_tcpwrappers__allow('allow_stunnel_nfs') \
          .with_pattern(['any']) }
        it { is_expected.to create_pki__copy('stunnel_nfs') }
        it { is_expected.to contain_class('stunnel::install') }
      end

      context 'when chrooted and pki true' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
          pki:     true
        }}
        let(:facts) {
          os_facts.merge(
            selinux_current_mode: 'disabled',
            selinux_enforced: false
          )
        }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_nfs') }
        it { is_expected.to create_file('/var/stunnel_nfs/etc/pki/cacerts') \
          .that_requires('Pki::Copy[stunnel_nfs]') }
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/chroot-systemd.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_nfs.conf') \
            .with_content(/.*chroot = \/var\/stunnel_nfs.*/)}
          it { is_expected.to create_file('/etc/systemd/system/stunnel_nfs.service') \
            .with_content(service_file) }
        else
          let(:service_file) { File.read('spec/expected/instance/chroot-init.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_nfs.conf') \
            .with_content(/.*chroot = \/var\/stunnel_nfs.*/)}
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_nfs') \
            .with_content(service_file) }
        end
      end

      # This behavior is not recommended or supported
      context 'when chrooted and selinux enabled' do
        let(:title) { 'sel' }
        let(:params) {{
          connect: [2049],
          accept:  20490,
          pki:     true,
          chroot:  '/var/stunnel_sel'
        }}
        let(:facts) {
          os_facts.merge(
            selinux_current_mode: 'enforcing',
            selinux_enforced: true
          )
        }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel::install') }
        it { is_expected.to create_file('/var/stunnel_sel') }
        it { is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts') }
        it { is_expected.to create_file('/var/stunnel_sel/etc/pki/cacerts') \
          .that_requires('Pki::Copy[stunnel_sel]') }
        if os_facts[:os][:release][:major].to_i >= 7
          let(:service_file) { File.read('spec/expected/instance/chroot-sel-systemd.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_sel.conf') \
            .with_content(/.*chroot = \/var\/stunnel_sel.*/)}
          it { is_expected.to create_file('/etc/systemd/system/stunnel_sel.service') \
            .with_content(service_file) }
        else
          let(:service_file) { File.read('spec/expected/instance/chroot-sel-init.txt') }

          it { is_expected.to contain_file('/etc/stunnel/stunnel_sel.conf') \
            .with_content(/.*chroot = \/var\/stunnel_sel.*/)}
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_sel') \
            .with_content(service_file) }
        end
      end

      # Make sure there are no resource issues when including legacy stunnel
      context 'when including (legacy) stunnel' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:pre_condition) { <<-EOF
          include 'stunnel'
          EOF
        }
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_class('stunnel') }
        it { is_expected.to contain_class('stunnel::config') }
        it { is_expected.to contain_class('stunnel::service') }
        it { is_expected.to contain_class('stunnel::install') }
      end

      context 'when selinux is disabled' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:facts) { os_facts.merge(selinux_enforced: false) }

        if os_facts[:os][:release][:major].to_i >= 7
          it { is_expected.to create_file('/etc/systemd/system/stunnel_nfs.service') \
            .without_content(/system_u:object_r:stunnel_var_run_t/)}
        else
          it { is_expected.to create_file('/etc/rc.d/init.d/stunnel_nfs') \
            .without_content(/^\s+mkdir -p system_u:object_r:stunnel_var_run_t/)}
        end
      end

      context 'on an unsupported OS' do
        let(:params) {{
          connect: [2049],
          accept:  20490,
        }}
        let(:facts) { os_facts.merge(init_systems: ['rc']) }
        it { is_expected.to compile.and_raise_error(/Init systems.*not supported/) }
      end
    end
  end
end
