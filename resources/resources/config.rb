# Cookbook Name:: logstash
#
# Resource:: config
#

actions :add, :remove, :register, :deregister
default_action :add

attribute :user, :kind_of => String, :default => "logstash"
attribute :logstash_dir, :kind_of => String, :default => "/etc/logstash"
attribute :pipelines_dir, :kind_of => String, :default => "/etc/logstash/pipelines"
attribute :cdomain, :kind_of => String, :default => "redborder.cluster"
attribute :managers_all, :kind_of => Array, :default => []
attribute :flow_nodes, :kind_of => Array, :default => []
attribute :scanner_nodes, :kind_of => Array, :default => []
attribute :vault_nodes, :kind_of => Array, :default => []
attribute :device_nodes, :kind_of => Array, :default => []
attribute :namespaces, :kind_of => Array, :default => []
attribute :memcached_server, :kind_of => String, :default => "memcached.service"
attribute :mac_vendors, :kind_of => String, :default => "/etc/objects/mac_vendors"
attribute :mongo_cve_database, :kind_of => String, :default => 'cvedb'
attribute :mongo_port, :kind_of => String, :default => '27017'
attribute :logstash_pipelines, :kind_of => Array, :default => []

# EXAMPLES

#attribute :myinteger, :kind_of => Fixnum, :default => 1
#attribute :myarray, :kind_of => Array, :default => ["val1"]
#attribute :myhash, :kind_of => Object, :default => {"val1" => "1"}
#attribute :myboolean, :kind_of => [TrueClass, FalseClass], :default => true
