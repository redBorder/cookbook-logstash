
# Cookbook Name:: logstash
#
# Provider:: config
#

include Logstash::Helper

action :add do
  begin
    user = new_resource.user
    cdomain = new_resource.cdomain
    flow_nodes = new_resource.flow_nodes
    vault_nodes = new_resource.vault_nodes
    managers_all = new_resource.managers_all
    namespaces = new_resource.namespaces
    memcached_server = new_resource.memcached_server
    mac_vendors = new_resource.mac_vendors

    yum_package "logstash" do
      action :upgrade
      flush_cache [:before]
    end

    yum_package "redborder-logstash-plugins" do
      action :upgrade
      flush_cache [:before]
    end

    user user do
      action :create
      system true
    end

    managers_all = get_managers
    logstash_hash_item = data_bag_item("passwords","vault") rescue logstash_hash_item = { "hash_key" => node["redborder"]["rsyslog"]["hash_key"], "hash_function" => node["redborder"]["rsyslog"]["hash_function"] }

    %w[ /etc/logstash /etc/logstash/pipelines /etc/logstash/pipelines/sflow /etc/logstash/pipelines/netflow /etc/logstash/pipelines/vault ].each do |path|
      directory path do
        owner user
        group user
        mode 0755
        action :create
      end
    end

    template "/etc/logstash/logstash.yml" do
      source "logstash.yml.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:user => user)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines.yml" do
      source "pipelines.yml.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    # Vault pipeline

    template "/etc/logstash/pipelines/vault/00_input.conf" do
      source "input_kafka.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:topics => ["rb_vault"])
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/01_generic.conf" do
      source "vault_generic.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:hash_key => logstash_hash_item["hash_key"], :hash_function => logstash_hash_item["hash_function"])
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/02_sshd.conf" do
      source "vault_sshd.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/03_iptables.conf" do
      source "vault_iptables.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/04_nginx.conf" do
      source "vault_nginx.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/05_dnsmasq.conf" do
      source "vault_dnsmasq.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/06_addfields.conf" do
      source "vault_addfields.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/vault/99_output.conf" do
      source "output_kafka.conf.erb"
      owner "root"
      owner "root"
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:input_topics => ["rb_vault"],
                :output_topic => "rb_vault_post"
               )
      notifies :restart, "service[logstash]", :delayed
    end

    # sflow pipeline
    
    template "/etc/logstash/pipelines/sflow/00_input.conf" do
      source "input_kafka.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:topics => ["sflow"])
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/01_tagging.conf" do
      source "sflow_tagging.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:flow_nodes => flow_nodes)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/02_normalization.conf" do
      source "sflow_normalization.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/03_enrichment.conf" do
      source "sflow_enrichment.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:flow_nodes => flow_nodes)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/04_field_conversion.conf" do
      source "sflow_field_conversion.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/91_rename.conf" do
      source "sflow_rename.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/sflow/99_output.conf" do
      source "output_kafka.conf.erb"
      owner "root"
      owner "root"
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:input_topics => ["sflow"],
                :output_topic => "rb_flow"
               )
      notifies :restart, "service[logstash]", :delayed
    end

    # netflow pipeline

    template "/etc/logstash/pipelines/netflow/00_input.conf" do
      source "input_kafka.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:topics => ["rb_flow"])
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/01_macscrambling.conf" do
      source "netflow_macscrambling.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:memcached_server => memcached_server)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/02_geoenrich.conf" do
      source "netflow_geoenrich.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/03_macvendor.conf" do
      source "netflow_macvendor.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:memcached_server => memcached_server,
                :mac_vendors => mac_vendors
      )
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/04_darklist.conf" do
      source "netflow_darklist.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:memcached_server => memcached_server)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/90_splitflow.conf" do
      source "netflow_splitflow.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:memcached_server => memcached_server)
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/91_rename.conf" do
      source "netflow_rename.conf.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      notifies :restart, "service[logstash]", :delayed
    end

    template "/etc/logstash/pipelines/netflow/99_output.conf" do
      source "output_kafka_namespace.conf.erb"
      owner "root"
      owner "root"
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:input_topics => ["rb_flow"],
                :output_topic => "rb_flow_post",
                :namespaces => namespaces
      )
      notifies :restart, "service[logstash]", :delayed
    end

    # end of pipelines

    #logstash rules
    directory "/etc/logstash/pipelines/vault/patterns" do
      owner "root"
      group "root"
      mode 0755
      action :create
    end

    directory "/share/logstash-rules" do
      owner "root"
      group "root"
      mode 0755
      action :create
      recursive true
    end

    Dir.foreach("/var/chef/cookbooks/logstash/templates/patterns") do |f|
      next if f == '.' or f == '..'
      template "/share/logstash-rules/#{f}" do
        source "patterns/#{f}"
        owner "root"
        group "root"
        mode 0644
        cookbook "logstash"
        ignore_failure true
        notifies :restart, "service[logstash]", :delayed
      end
    end

    Dir.foreach("/share/logstash-rules") do |f|
      next if f == '.' or f == '..'
      link "/etc/logstash/pipelines/vault/patterns/#{f}" do
        to "/share/logstash-rules/#{f}"
      end
    end

    service "logstash" do
      service_name "logstash"
      ignore_failure true
      supports :status => true, :reload => true, :restart => true, :enable => true
      action [:start, :enable]
    end

    Chef::Log.info("Logstash cookbook has been processed")
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :remove do
  begin
    
    service "logstash" do
      service_name "logstash"
      ignore_failure true
      supports :status => true, :enable => true
      action [:stop, :disable]
    end

    %w[ /etc/logstash ].each do |path|
      directory path do
        recursive true
        action :delete
      end
    end

    yum_package "logstash" do
      action :remove
    end

    yum_package "redborder-logstash-plugins" do
      action :remove
    end

    Chef::Log.info("Logstash cookbook has been processed")
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :register do
  begin
    if !node["logstash"]["registered"]
      query = {}
      query["ID"] = "logstash-#{node["hostname"]}"
      query["Name"] = "logstash"
      query["Address"] = "#{node["ipaddress"]}"
      query["Port"] = "5000"
      json_query = Chef::JSONCompat.to_json(query)

      execute 'Register service in consul' do
         command "curl http://localhost:8500/v1/agent/service/register -d '#{json_query}' &>/dev/null"
         action :nothing
      end.run_action(:run)

      node.set["logstash"]["registered"] = true
      Chef::Log.info("Logstash service has been registered to consul")
    end
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :deregister do
  begin
    if node["logstash"]["registered"]
      execute 'Deregister service in consul' do
        command "curl http://localhost:8500/v1/agent/service/deregister/logstash-#{node["hostname"]} &>/dev/null"
        action :nothing
      end.run_action(:run)

      node.set["logstash"]["registered"] = false
      Chef::Log.info("Logstash service has been deregistered from consul")
    end
  rescue => e
    Chef::Log.error(e.message)
  end
end
