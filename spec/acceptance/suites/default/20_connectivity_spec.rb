require 'spec_helper_acceptance'

test_name 'instance connectivity'

describe 'instance connectivity' do

  if hosts.count < 2
    it 'only runs with more than one host' do
      skip('You need at least two hosts in your nodeset to run this test')
    end
  else
    context 'system prep' do
      hosts.each do |host|
        install_package(host, 'nc')
      end
    end

    context 'set up a bi-directional connection set' do
      hosts.each do |server|
        hosts.each do |client|

          server_fqdn = fact_on(server, 'fqdn')

          hieradata = {
            'iptables::ports'            => { 22 => { 'proto' => 'tcp', 'trusted_nets' => ['ALL'] } },
            'iptables::precise_match'    => true,
            'simp_options::firewall'     => true,
            'simp_options::pki'          => true,
            'simp_options::pki::source'  => '/etc/pki/simp-testing/pki/',
            'simp_options::trusted_nets' => [client.ip]
          }

          manifest = <<-EOF
            stunnel::instance { 'mysvc':
              client  => false,
              connect => [1234],
              accept  => 12345
            }

            stunnel::instance { 'mysvc-client':
              client  => true,
              connect => ['#{server_fqdn}:12345'],
              accept  => 1235,
              require => Stunnel::Instance['mysvc']
            }
          EOF

          context "with server #{server} and client #{client}" do
            [server, client].each do |host|
              it "should clean up #{host}" do
                on(host, 'pkill -f nc', :accept_all_exit_codes => true)
              end

              it "should apply on #{host} with no errors" do
                set_hieradata_on(host, hieradata)
                apply_manifest_on(host, manifest)
              end

              it "should be idempotent on #{host}" do
                apply_manifest_on(host, manifest, catch_changes: true)
              end
            end

            it "should set up netcat to listen on #{server}" do
              on(server, 'nc -k -l 1234 > /tmp/ncout.txt 2>&1 &')
            end

            it "should send successfully from #{client}" do
              on(client, %(/bin/echo "#{client.ip}" | nc localhost 1235))
            end

            it "should be received successfully on #{server}" do
              output = on(server, 'tail -n1 /tmp/ncout.txt').stdout.strip
              expect(output).to eq client.ip
            end
          end
        end
      end
    end
  end
end
