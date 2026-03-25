require 'spec_helper_acceptance'
require 'timeout'

test_name 'connection'

describe 'connection' do
  hosts.each do |host|
    let(:hieradata) do
      {
        'iptables::ports'            => { 22 => { 'proto' => 'tcp', 'trusted_nets' => ['ALL'] } },
        'simp_options::haveged'      => true,
        'simp_options::firewall'     => true,
        'simp_options::pki'          => true,
        'simp_options::pki::source'  => '/etc/pki/simp-testing/pki/',
        'simp_options::trusted_nets' => ['ALL'],
      }
    end
    let(:base_manifest) do
      <<~EOF
        stunnel::connection { 'nfs':
          connect => [2049],
          accept  => 20490,
        }
        stunnel::connection { 'rsync':
          connect => [3049],
          accept  => 30490,
        }
      EOF
    end
    let(:domain) { fact_on(host, 'domain') }

    # This test verifies the validity of basic stunnel configurations
    # and ensures multiple connections can co-exist as advertised. It
    # does not test stunnel itself.
    context 'with selinux on' do
      it 'applies with no errors' do
        enable_epel_on(host)

        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, base_manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, base_manifest, catch_changes: true)
      end

      it 'is running stunnel in one monolithic process' do
        on(host, 'systemctl status stunnel')
      end

      [20_490, 30_490].each do |port|
        it "stunnel should be listening on #{port}" do
          on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
        end
      end
    end

    context 'with selinux off' do
      context 'before reboot' do
        it 'disables selinux without a reboot' do
          set_hieradata_on(host, hieradata)

          manifest = base_manifest + <<~EOF
            class { 'selinux': ensure => 'disabled' }
          EOF
          apply_manifest_on(host, manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Permissive')
        end

        it 'applies with no errors' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, base_manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, base_manifest, catch_changes: true)
        end

        it 'is running stunnel in one monolithic process' do
          on(host, 'systemctl status stunnel')
        end

        [20_490, 30_490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end

      context 'after reboot' do
        it 'reboots and have selinux disabled' do
          # There is an issue in which the domain fact ceases to exist after
          # reboot, because NetworkManager generates an empty /etc/resolv.conf.
          # To work around this problem, backup /etc/resolv.conf and restore
          # as needed.
          on(host, 'cp /etc/resolv.conf /etc/resolv.conf.bak')
          host.reboot

          if on(host, 'grep nameserver /etc/resolv.conf', accept_all_exit_codes: true).stdout.strip.empty?
            on(host, 'cp /etc/resolv.conf.bak /etc/resolv.conf')
          end

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Disabled')

          apply_manifest_on(host, base_manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, base_manifest, catch_changes: true)
        end

        it 'is running stunnel in one monolithic process' do
          on(host, 'systemctl status stunnel')
        end

        [20_490, 30_490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end
    end

    context 'with selinux re-enabled' do
      context 'before reboot' do
        it 'reenables selinux without a reboot' do
          set_hieradata_on(host, hieradata)

          manifest = base_manifest + <<~EOF
            class { 'selinux': ensure => 'enforcing' }
          EOF
          apply_manifest_on(host, manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Disabled')
        end

        it 'applies with no errors' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, base_manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, base_manifest, catch_changes: true)
        end

        it 'is running stunnel in one monolithic process' do
          on(host, 'systemctl status stunnel')
        end

        [20_490, 30_490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end

      context 'after reboot' do
        it 'reboots and have selinux enforcing' do
          on(host, 'puppet resource service stunnel ensure=stopped enable=false')
          host.reboot

          if on(host, 'grep nameserver /etc/resolv.conf', accept_all_exit_codes: true).stdout.strip.empty?
            # Restore working resolv.conf, as it has been munged by NetworkManager
            on(host, 'cp /etc/resolv.conf.bak /etc/resolv.conf')
          end

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Enforcing')

          apply_manifest_on(host, base_manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, base_manifest, catch_changes: true)
        end

        it 'is running stunnel in one monolithic process' do
          on(host, 'systemctl status stunnel')
        end

        [20_490, 30_490].each do |port|
          it "stunnel should be listening on #{port}" do
            on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
          end
        end
      end
    end
  end
end
