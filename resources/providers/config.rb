
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
    managers_all = new_resource.managers_all

    yum_package "logstash" do
      action :upgrade
      flush_cache [:before]
    end

    user user do
      action :create
      system true
    end

    managers_all = get_managers
    flow_nodes = get_sensors_info("flow-sensor")
    logstash_hash_item = data_bag_item("passwords","vault") rescue logstash_hash_item = { "hash_key" => "0123456789", "hash_function" => "SHA256" }

    %w[ /etc/logstash /etc/logstash/pipelines /etc/logstash/pipelines/sflow /etc/logstash/pipelines/vault ].each do |path|
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

    # TODO: normalize and enrich sflow
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

    # end of pipelines

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
