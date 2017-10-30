require 'spec_helper_acceptance'

test_name 'connection'

describe 'connection' do
  hosts.each do |host|

    let(:base_hieradata) {{
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


    # This test verifies the validity of basic stunnel configurations
    # and ensures multiple connections can co-exist as advertised. It
    # does not test stunnel itself.
    context 'with selinux on' do
      it 'should apply with no errors' do
        install_package(host, 'epel-release')
        set_hieradata_on(host,base_hieradata)
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
          hieradata = base_hieradata.merge({'simp_options::selinux' => false})
          set_hieradata_on(host,hieradata)
          on(host, 'cat /etc/puppetlabs/code/hieradata/default.yaml')

          manifest = base_manifest + <<-EOF
            class { 'selinux': ensure => 'disabled' }
          EOF
          apply_manifest_on(host,manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Permissive')
        end

        it 'should apply with no errors' do
          set_hieradata_on(host,base_hieradata)
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
          host.reboot

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
          hieradata = base_hieradata.merge({'simp_options::selinux' => true})
          set_hieradata_on(host,hieradata)
          on(host, 'cat /etc/puppetlabs/code/hieradata/default.yaml')

          manifest = base_manifest + <<-EOF
            class { 'selinux': ensure => 'enforcing' }
          EOF
          apply_manifest_on(host,manifest, catch_failures: true)

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Disabled')
        end

        it 'should apply with no errors' do
          set_hieradata_on(host,base_hieradata)
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

          result = on(host, 'getenforce')
          expect(result.stdout).to include('Enforcing')
          on(host, "echo domain #{domain} >> /etc/resolv.conf")
          on(host, "echo search #{domain} >> /etc/resolv.conf")

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
