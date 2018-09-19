require 'spec_helper_acceptance'

test_name 'instance connectivity'

describe 'instance connectivity' do

  if hosts.count < 2
    it 'only runs with more than one host' do
      skip('You need at least two hosts in your nodeset to run this test')
    end
  else
    let(:manifest) { <<-EOF
      stunnel::instance { 'mysvc':
        client  => false,
        connect => [1234],
        accept  => 12345
      }

      stunnel::instance { 'mysvc-client':
        client  => true,
        connect => ['#{server_fqdn}:12345'],
        accept  => 1235
      }
      EOF
    }

    let(:hieradata) {{
      'simp_options::pki'          => true,
      'simp_options::pki::source'  => '/etc/pki/simp-testing/pki/',
      'simp_options::trusted_nets' => [client_fqdn]
    }}

    server = hosts[0]
    client = hosts[1]

    let(:server_fqdn) { fact_on(server, 'fqdn') }
    let(:client_fqdn) { fact_on(client, 'fqdn') }

    context 'set up a bi-directional connection set' do
      hosts.each do |host|

        context "on #{host}" do
          # FIXME: Need to disable firewalld by default in base OEL box in the future
          # Account for this now by stopping the service
          it 'should disable firewalld if necessary' do
            if fact_on(host, 'operatingsystem').strip == 'OracleLinux' and fact_on(host, 'operatingsystemmajrelease').strip == '7'
              on(host, 'puppet resource service firewalld ensure=stopped enable=false')
            end
          end

          it 'should apply with no errors' do
            set_hieradata_on(host, hieradata)
            apply_manifest_on(host, manifest)
          end

          it 'should be idempotent' do
            apply_manifest_on(host, manifest, catch_changes: true)
          end

          it 'should set up netcat to listen' do
            host.install_package('nc')
            on(host, 'nc -k --listen 1234 > /tmp/ncout.txt 2>&1 &')
          end
        end
      end
    end

    context 'test a passed message' do
      it 'should send from the client' do
        on(client, %(/bin/echo "#{client_fqdn}" | nc localhost 1235))
        output = on(server, 'tail -n1 /tmp/ncout.txt').stdout.strip

        expect(output).to eq client_fqdn
      end
    end
  end
end
