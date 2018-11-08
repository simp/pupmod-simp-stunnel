require 'spec_helper_acceptance'
require 'timeout'

test_name 'connection'

describe 'connection' do
  hosts.each do |host|

    let(:hieradata) {{
      'simp_options::pki'          => true,
      'simp_options::pki::source'  => '/etc/pki/simp-testing/pki/',
      'simp_options::trusted_nets' => ['ANY']
    }}
    let(:base_manifest) { <<-EOF
        stunnel::connection { 'nfs':
          connect => [2049],
          accept  => 20490,
        }
        stunnel::connection { 'rsync':
          connect => [3049],
          accept  => 30490
        }
      EOF
    }
    let(:domain) { fact_on(host, 'domain') }

    # The old version of the module used a SysV style init script, which is no
    # longer used in the newer versions. However, the process started from the
    # older init script may still be running. This will cause the new systemd
    # unit to fail to start, citing the port already being in use.
    context 'with an existing stunnel process on el7' do
      if fact_on(host, 'operatingsystemmajrelease').to_s >= '7' && fact_on(host, 'operatingsystem') != 'OracleLinux'
        let(:hostname) { fact_on(host, 'hostname') }
        let(:minion_stunnel_conf) { <<-EOF
            debug = err
            syslog = yes
            pid = /var/run/stunnel/stunnel.pid
            foreground = no
            [nfs]
            connect = 0.0.0.0:2049
            accept = 20490
            failover = rr
            key = /etc/pki/simp-testing/pki/private/#{hostname}.#{domain}.pem
            cert = /etc/pki/simp-testing/pki/public/#{hostname}.#{domain}.pub
            CAfile = /etc/pki/simp-testing/pki/cacerts/cacerts.pem
            CRLpath = /etc/pki/simp-testing/pki/crl
            ciphers = HIGH:-SSLv2
            verify = 2
            delay = no
            retry = no
            renegotiation = yes
            reset = yes
          EOF
        }
        it 'should kill running stunnel process started with old SysV-type init script' do
          create_remote_file(host, '/etc/stunnel/stunnel.conf', minion_stunnel_conf)
          scp_to(host,'spec/expected/legacy_el7_init.txt','/etc/rc.d/init.d/stunnel_legacy')
          on(host, 'mkdir -p /var/run/stunnel')
          on(host, 'chmod +x /etc/rc.d/init.d/stunnel_legacy')

          on(host, 'chown -R root:root /etc/pki/simp-testing/pki')
          on(host, 'chmod -R go+r /etc/pki/simp-testing/pki')
          on(host, 'chcon -R --type cert_t /etc/pki/simp-testing/pki')
          on(host, 'SYSTEMCTL_SKIP_REDIRECT=yes /etc/rc.d/init.d/stunnel_legacy start')
          pid = on(host, 'cat /var/run/stunnel/stunnel.pid').stdout.strip
          on(host, "ps -f --pid #{pid}")

          apply_manifest_on(host,base_manifest, catch_failures: true)
          apply_manifest_on(host,base_manifest, catch_changes: true)
          on(host, "ps -f --pid #{pid}", :acceptable_exit_codes => [1])
        end
      end
    end

    # This test verifies the validity of basic stunnel configurations
    # and ensures multiple connections can co-exist as advertised. It
    # does not test stunnel itself.
    context 'with selinux on' do
      it 'should apply with no errors' do
        install_package(host, 'epel-release')
        set_hieradata_on(host,hieradata)
        apply_manifest_on(host,base_manifest, catch_failures: true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host,base_manifest, catch_changes: true)
      end

      it 'should be running stunnel in one monolithic process' do
        if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
          on(host, 'systemctl status stunnel')
        else
          on(host, 'service stunnel status')
        end
      end

      [20490,30490].each do |port|
        it "stunnel should be listening on #{port}" do
          on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
        end
      end
    end

    context 'with selinux off' do
      context 'before reboot' do
        it 'should disable selinux without a reboot' do
          set_hieradata_on(host,hieradata)

          manifest = base_manifest + <<-EOF
            class { 'selinux': ensure => 'disabled' }
          EOF
          apply_manifest_on(host,manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Permissive')
        end

        it 'should apply with no errors' do
          set_hieradata_on(host,hieradata)
          apply_manifest_on(host,base_manifest, catch_failures: true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host,base_manifest, catch_changes: true)
        end

        it 'should be running stunnel in one monolithic process' do
          if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
            on(host, 'systemctl status stunnel')
          else
            on(host, 'service stunnel status')
          end
        end

        [20490,30490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end

      context 'after reboot' do
        it 'should reboot and have selinux disabled' do
          # There is an issue in which the domain fact ceases to exist after
          # reboot, because NetworkManager generates an empty /etc/resolv.conf.
          # To work around this problem, backup /etc/resolv.conf and restore
          # as needed.
          on(host,'cp /etc/resolv.conf /etc/resolv.conf.bak')
          host.reboot

          if on(host, 'grep nameserver /etc/resolv.conf', :accept_all_exit_codes => true).stdout.strip.empty?
            on(host, 'cp /etc/resolv.conf.bak /etc/resolv.conf')
          end

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Disabled')

          apply_manifest_on(host,base_manifest, catch_failures: true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host,base_manifest, catch_changes: true)
        end

        it 'should be running stunnel in one monolithic process' do
          if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
            on(host, 'systemctl status stunnel')
          else
            on(host, 'service stunnel status')
          end
        end

        [20490,30490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end
    end

    context 'with selinux re-enabled' do
      context 'before reboot' do
        it 'should reenable selinux without a reboot' do
          set_hieradata_on(host,hieradata)

          manifest = base_manifest + <<-EOF
            class { 'selinux': ensure => 'enforcing' }
          EOF
          apply_manifest_on(host,manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Disabled')
        end

        it 'should apply with no errors' do
          set_hieradata_on(host,hieradata)
          apply_manifest_on(host,base_manifest, catch_failures: true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host,base_manifest, catch_changes: true)
        end

        it 'should be running stunnel in one monolithic process' do
          if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
            on(host, 'systemctl status stunnel')
          else
            on(host, 'service stunnel status')
          end
        end

        [20490,30490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end

      context 'after reboot' do
        it 'should reboot and have selinux enforcing' do
          on(host, "puppet resource service stunnel ensure=stopped enable=false")
          host.reboot

          if on(host, 'grep nameserver /etc/resolv.conf', :accept_all_exit_codes => true).stdout.strip.empty?
            # Restore working resolv.conf, as it has been munged by NetworkManager
            on(host, 'cp /etc/resolv.conf.bak /etc/resolv.conf')
          end

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Enforcing')

          apply_manifest_on(host,base_manifest, catch_failures: true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host,base_manifest, catch_changes: true)
        end

        it 'should be running stunnel in one monolithic process' do
          if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
            on(host, 'systemctl status stunnel')
          else
            on(host, 'service stunnel status')
          end
        end

        [20490,30490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end
    end
  end
end
