# Cookbook Name:: logstash
#
# Resource:: config
#

actions :add, :remove, :register, :deregister
default_action :add

attribute :user, :kind_of => String, :default => "logstash"
attribute :cdomain, :kind_of => String, :default => "redborder.cluster"

# EXAMPLES

#attribute :myinteger, :kind_of => Fixnum, :default => 1
#attribute :myarray, :kind_of => Array, :default => ["val1"]
#attribute :myhash, :kind_of => Object, :default => {"val1" => "1"}
#attribute :myboolean, :kind_of => [TrueClass, FalseClass], :default => true
