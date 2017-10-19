require 'spec_helper_acceptance'

test_name 'instance'

describe 'instance' do
  hosts.each do |host|

    # This test verifies the validity of basic stunnel configurations
    # and ensures multiple connections can co-exist as advertised. It
    # does not test stunnel itself.
    context 'set up legacy, chrooted, and non-chrooted connections' do
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

      it 'should apply with no errors' do
        install_package(host, 'epel-release')
        set_hieradata_on(host,hieradata)
        apply_manifest_on(host,manifest, catch_failures: true)
        apply_manifest_on(host,manifest, catch_failures: true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host,manifest,catch_changes: true)
      end


      it 'should be running stunnel, stunnel_nfs, and stunnel chroot' do
        if fact_on(host, 'operatingsystemmajrelease').to_s >= '7'
          on(host, 'systemctl status stunnel')
          on(host, 'systemctl status stunnel_nfs')
          on(host, 'systemctl status stunnel_chroot')
        else
          on(host, 'service stunnel status')
          on(host, 'service stunnel_nfs status')
          on(host, 'service stunnel_chroot status')
        end
      end

      it 'stunnel_nfs should be listening on 20490' do
        pid = on(host, 'cat /var/run/stunnel/stunnel_nfs.pid').stdout.strip
        result = on(host, "netstat -plant | grep #{pid} | awk ' { print $4 }'").stdout.strip
        expect(result).to match(/0.0.0.0:20490/)
      end

      it 'stunnel_chroot should be listening on 40490' do
        pid = on(host, 'cat /var/stunnel_chroot/var/run/stunnel/stunnel_chroot.pid').stdout.strip
        result = on(host, "netstat -plant | grep #{pid} | awk ' { print $4 }'").stdout.strip
        expect(result).to match(/0.0.0.0:40490/)
      end
    end

    context 'clean up' do
      it 'should stop and clean up stunnel' do
        %w(stunnel stunnel_chroot stunnel_nfs).each do |service|
          on(host, "puppet resource service #{service} ensure=stopped enable=false")
        end
        # on(host, 'rm -rf /etc/stunnel/*')   # Remove configuration
        # on(host, 'rm -rf /var/stunnel*')    # Remove chroots
        on(host, 'service network restart') # Some network wackiness
        # Get rid of stunnels
        on(host, "ps aux | grep -ie stunnel | grep -v 'grep' | awk '{print $2}' | xargs --no-run-if-empty kill -9")
      end
    end
  end
end
