#! /usr/bin/env ruby -S rspec
require 'spec_helper'

describe Puppet::Type.type(:stunnel_instance_purge) do
  let :stunnel_instance_purge do
    Puppet::Type.type(:stunnel_instance_purge).new(:name => 'test', :verbose => false, :dirs => ['/test'])
  end

  it 'should accept a verbose flag' do
    stunnel_instance_purge[:verbose] = true
    expect(stunnel_instance_purge[:verbose]).to eq(true)
  end

  it 'should accept an Array of target directories' do
    stunnel_instance_purge[:dirs] = ['/foo', '/bar']
    expect(stunnel_instance_purge[:dirs]).to eq(['/foo', '/bar'])
  end

  it 'should accept an absolute path for all :dirs entries' do
    expect {
      Puppet::Type.type(:stunnel_instance_purge).new(
        :name => 'test',
        :dirs => [
          '/foo',
          '/bar',
          '/foo/bar/baz/stuff'
        ]
      )
    }.not_to raise_error
  end

  it 'should not accept non-absolute paths for any :dirs entries' do
    expect {
      Puppet::Type.type(:stunnel_instance_purge).new(
        :name => 'test',
        :dirs => [
          '/foo',
          '/bar',
          'foo/bar/baz/stuff'
        ]
      )
    }.to raise_error(/Invalid value.*"foo/)
  end
end
