require 'spec_helper_acceptance'

test_name 'instance'

describe 'instance' do
  hosts.each do |host|
    let(:manifest) { <<-EOF
      stunnel::instance { 'nfs':
        client  => false,
        connect => [2049],
        accept  => 20490,
      }
      stunnel::instance { 'chroot':
        client  => false,
        connect => [4049],
        accept  => 40490,
        chroot  => '/var/stunnel_chroot'
      }
      stunnel::connection { 'rsync':
        client  => false,
        connect => [3049],
        accept  => 30490
      }
      EOF
    }
    let(:hieradata) {{
      'simp_options::pki'          => true,
      'simp_options::pki::source'  => '/etc/pki/simp-testing/pki/',
      'simp_options::trusted_nets' => ['ANY']
    }}

    # This test verifies the validity of basic stunnel configurations
    # and ensures multiple connections can co-exist as advertised. It
    # does not test stunnel itself.
    context 'set up legacy, chrooted, and non-chrooted connections' do
      it 'should apply with no errors' do
        set_hieradata_on(host,hieradata)
        apply_manifest_on(host,manifest)
      end

      it 'should be idempotent' do
        apply_manifest_on(host,manifest, catch_changes: true)
      end


      it 'should be running stunnel, stunnel_managed_by_puppet_nfs, and stunnel_managed_by_puppet_chroot' do
        if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
          on(host, 'systemctl status stunnel')
          on(host, 'systemctl status stunnel_managed_by_puppet_nfs')
          on(host, 'systemctl status stunnel_managed_by_puppet_chroot')
        else
          on(host, 'service stunnel status')
          on(host, 'service stunnel_managed_by_puppet_nfs status')
          on(host, 'service stunnel_managed_by_puppet_chroot status')
        end
      end

      [20490,30490,40490].each do |port|
        it "stunnel should be listening on #{port}" do
          install_package(host, 'lsof')
          on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
        end
      end
    end

    context 'killing one instance should not kill the rest' do
      it 'should have all services running' do
        apply_manifest_on(host,manifest, catch_failures: true)
      end
      it 'after killing an instanced stunnel, have the other stunnel still running' do
        on(host, 'puppet resource service stunnel_managed_by_puppet_nfs ensure=stopped enable=false')

        [
          'stunnel_managed_by_puppet_chroot',
          'stunnel'
        ].each do |service|
          result = on(host, "puppet resource service #{service}").stdout
          expect(result).to match(/running/)
        end
        on(host, 'netstat -plant | grep `lsof -ti :20490` | grep stunnel', acceptable_exit_codes: [1])
        [30490,40490].each do |port|
          on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
        end
      end
      it 'should restart all services' do
        apply_manifest_on(host,manifest, catch_failures: true)
      end
      it 'should kill the monolithic stunnel and have instances still running' do
        on(host, 'puppet resource service stunnel ensure=stopped enable=false')

        [
          'stunnel_managed_by_puppet_chroot',
          'stunnel_managed_by_puppet_nfs'
        ].each do |service|
          result = on(host, "puppet resource service #{service}").stdout
          expect(result).to match(/running/)
        end
        on(host, 'netstat -plant | grep `lsof -ti :30490` | grep stunnel', acceptable_exit_codes: [1])
        [20490,40490].each do |port|
          on(host, "netstat -plant | grep `lsof -ti :#{port}` | grep stunnel")
        end
      end
    end

    context 'renaming an stunnel session but keeping the same port' do
      rename_manifest = <<-EOM
        stunnel::instance { 'new_test_service':
          client  => false,
          connect => [5049],
          accept  => 50490
        }
      EOM

      it 'should succeed' do
        apply_manifest_on(host, rename_manifest)
      end

      it 'should clean up old config files' do
        result = on(host, 'ls /etc/stunnel/*nfs*', :accept_all_exit_codes => true).stdout.strip
        expect(result).to be_empty
      end
    end

    context 'clean up' do
      it 'should stop and clean up stunnel' do
        [
          'stunnel',
          'stunnel_managed_by_puppet_chroot',
          'stunnel_managed_by_puppet_nfs'
        ].each do |service|
          on(host, "puppet resource service #{service} ensure=stopped enable=false")
        end
      end
    end
  end
end
