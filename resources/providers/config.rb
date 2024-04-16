
# Cookbook Name:: logstash
#
# Provider:: config
#

include Logstash::Helper

action :add do
  begin
    user = new_resource.user
    logstash_dir = new_resource.logstash_dir
    pipelines_dir = new_resource.pipelines_dir
    cdomain = new_resource.cdomain                #TODO Deprecated?
    flow_nodes = new_resource.flow_nodes
    scanner_nodes = new_resource.scanner_nodes    #TODO Deprecated?
    vault_nodes = new_resource.vault_nodes        #TODO Deprecated?
    device_nodes = new_resource.device_nodes
    managers_all = new_resource.managers_all      #TODO Deprecated?
    namespaces = new_resource.namespaces  
    memcached_server = new_resource.memcached_server
    mac_vendors = new_resource.mac_vendors
    mongo_cve_database = new_resource.mongo_cve_database
    mongo_port = new_resource.mongo_port
    is_proxy = is_proxy?
    is_sensor = is_sensor?
    is_manager = is_manager?

    dnf_package "logstash-rules" do
      only_if { is_manager }
      action :upgrade
      flush_cache [:before]
    end

    dnf_package "logstash" do
      action :upgrade
      flush_cache [:before]
    end

    dnf_package "redborder-logstash-plugins" do
      action :upgrade
      flush_cache [:before]
    end

    execute "create_user" do
      command "/usr/sbin/useradd -r #{user}"
      ignore_failure true
      not_if "getent passwd #{user}"
    end

    logstash_hash_item = data_bag_item("passwords","vault") rescue logstash_hash_item = { "hash_key" => node["redborder"]["rsyslog"]["hash_key"], "hash_function" => node["redborder"]["rsyslog"]["hash_function"] }
    monitors_dg = data_bag_item("rBglobal", "monitors") rescue monitors_dg = {}

    db_redborder_secrets = data_bag_item("passwords", "db_redborder") rescue db_redborder_secrets = {}
    if !db_redborder_secrets.empty?
      database_name = db_redborder_secrets["database"]
      username = db_redborder_secrets["username"]
      password = db_redborder_secrets["pass"]
      port = db_redborder_secrets["port"]
      host = db_redborder_secrets["hostname"]
    end

    [logstash_dir, pipelines_dir].each do |dir|
      directory dir do
        owner user
        group user
        mode 0755
        action :create
      end
    end

    pipelines = []
    if is_manager
      pipelines = %w[ sflow netflow vault scanner nmsp location mobility meraki apstate radius rbwindow bulkstats redfish monitor ips intrusion ]
    elsif is_proxy
      pipelines = %w[ bulkstats redfish ]
    elsif is_sensor
      pipelines = %w[ ips intrusion ]
    end

    pipelines.each do |pipeline|
      directory "#{pipelines_dir}/#{pipeline}" do
        owner user
        group user
        mode 0755
        action :create
      end
    end

    template "#{logstash_dir}/logstash.yml" do
      source "logstash.yml.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:user => user)
      notifies :restart, 'service[logstash]', :delayed
    end

    template "#{logstash_dir}/pipelines.yml" do
      source "pipelines.yml.erb"
      owner user
      group user
      mode 0644
      ignore_failure true
      cookbook "logstash"
      variables(:is_manager => is_manager, :is_proxy => is_proxy, :is_sensor => is_sensor)
      notifies :restart, "service[logstash]", :delayed
    end

    # Vault pipeline
    if is_manager
      template "#{pipelines_dir}/vault/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_vault"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/01_generic.conf" do
        source "vault_generic.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:hash_key => logstash_hash_item["hash_key"], :hash_function => logstash_hash_item["hash_function"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/02_sshd.conf" do
        source "vault_sshd.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/03_iptables.conf" do
        source "vault_iptables.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/04_nginx.conf" do
        source "vault_nginx.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/05_dnsmasq.conf" do
        source "vault_dnsmasq.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/06_addfields.conf" do
        source "vault_addfields.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/vault/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_vault_post",
                  :namespaces => namespaces
        )
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # sflow pipeline
    if is_manager
      template "#{pipelines_dir}/sflow/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["sflow"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/01_tagging.conf" do
        source "sflow_tagging.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:flow_nodes => flow_nodes)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/02_normalization.conf" do
        source "sflow_normalization.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/03_enrichment.conf" do
        source "sflow_enrichment.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:flow_nodes => flow_nodes)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/04_field_conversion.conf" do
        source "sflow_field_conversion.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/91_rename.conf" do
        source "sflow_rename.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/sflow/99_output.conf" do
        source "output_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:input_topics => ["sflow"],
                  :output_topic => "rb_flow"
        )
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # netflow pipeline
    if is_manager
      template "#{pipelines_dir}/netflow/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_flow"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/01_macscrambling.conf" do
        source "netflow_macscrambling.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/02_geoenrich.conf" do
        source "netflow_geoenrich.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/03_macvendor.conf" do
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

      template "#{pipelines_dir}/netflow/04_darklist.conf" do
        source "netflow_darklist.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/90_splitflow.conf" do
        source "netflow_splitflow.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/91_rename.conf" do
        source "netflow_rename.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/netflow/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_flow_post",
                  :namespaces => namespaces
        )
        notifies :restart, "service[logstash]", :delayed
      end
    end

    #scanner pipeline
    if is_manager
      template "#{pipelines_dir}/scanner/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_scanner"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/scanner/01_normalization.conf" do
        source "scanner_normalization.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/scanner/02_mongocve.conf" do
        source "scanner_mongocve.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:mongo_port => mongo_port, :mongo_cve_database => mongo_cve_database)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/scanner/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_scanner_post",
                  :namespaces => namespaces
        )
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # NMSP pipeline
    if is_manager
      template "#{pipelines_dir}/nmsp/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_nmsp"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/nmsp/01_macscrambling.conf" do
        source "nmsp_macscrambling.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/nmsp/03_nmsp.conf" do
        source "nmsp_removefields.conf.erb"
        owner user
        group user
        mode 0644
        retries 2
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/nmsp/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_topics => ["rb_location"],
                  :output_namespace_topic => "rb_wireless",
                  :namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # Location pipeline
    if is_manager
      template "#{pipelines_dir}/location/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_loc"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/location/01_macscrambling.conf" do
        source "location_macscrambling.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/location/02_macvendor.conf" do
        source "netflow_macvendor.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:mac_vendors => mac_vendors)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/location/10_location.conf" do
        source "location_location.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/location/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_topics => ["rb_location"],
                  :output_namespace_topic => "rb_wireless",
                  :namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # Mobility pipeline
    if is_manager
      template "#{pipelines_dir}/mobility/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_location"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/mobility/01_mobility.conf" do
        source "mobility_removefields.conf.erb"
        owner user
        group user
        mode 0644
        retries 2
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/mobility/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_loc_post",
                  :namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # MERAKI pipeline
    if is_manager
      template "#{pipelines_dir}/meraki/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["sflow"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/meraki/01_macscrambling.conf" do
        source "meraki_macscrambling.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/meraki/03_meraki.conf" do
        source "meraki_removefields.conf.erb"
        owner user
        group user
        mode 0644
        retries 2
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/meraki/99_output.conf" do
        source "output_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_topic => "rb_location")
        notifies :restart, "service[logstash]", :delayed
      end
    end

    #freeradius pipeline
    if is_manager
      template "#{pipelines_dir}/radius/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_radius"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/radius/01_macscrambling.conf" do
        source "radius_macscrambling.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/radius/03_radius.conf" do
        source "radius_radius.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        ignore_failure true
        cookbook "logstash"
        retries 2
        variables(:memcached_server => memcached_server)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/radius/99_output.conf" do
        source "output_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_topic => "rb_location")
        notifies :restart, "service[logstash]", :delayed
      end
    end

    #apstate pipeline
    if is_manager
      template "#{pipelines_dir}/apstate/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_state"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/apstate/01_apstate.conf" do
        source "apstate_apstate.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/apstate/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_state_post",
                  :namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # Rbwindow pipelines
    if is_manager
      template "#{pipelines_dir}/rbwindow/00_input.conf" do
        source "rbwindow_00_input.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        retries 2
        variables(:memcached_server => memcached_server, :database_name => database_name, :host => host,
                  :password => password, :user => username, :port => port)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/rbwindow/99_output.conf" do
        source "rbwindow_99_output.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end
    end

    #Bulskstats pipeline
    if is_manager || is_proxy
      template "#{pipelines_dir}/bulkstats/00_input.conf" do
        source "bulkstats_input.conf.erb"
        owner user
        owner user
        mode 0644
        cookbook "logstash"
        retries 2
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/bulkstats/01_bulkstats.conf" do
        source "bulkstats_bulkstats.conf.erb"
        owner user
        owner user
        mode 0644
        cookbook "logstash"
        retries 2
        variables(:device_nodes => device_nodes)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/bulkstats/02_enrichment.conf" do
        source "bulkstats_enrichment.conf.erb"
        owner user
        owner user
        mode 0644
        cookbook "logstash"
        retries 2
        variables(:device_nodes => device_nodes)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/bulkstats/99_output.conf" do
        source "output_kafka.conf.erb"
        owner user
        owner user
        mode 0644
        cookbook "logstash"
        retries 2
        variables(:output_topic => "rb_monitor")
        notifies :restart, "service[logstash]", :delayed
      end
    end

    #Monitor pipeline
    if is_manager
      template "#{pipelines_dir}/monitor/00_input.conf" do
        source "input_kafka.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:topics => ["rb_monitor"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/monitor/01_monitor.conf" do
        source "monitor_removefields.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/monitor/99_output.conf" do
        source "output_kafka_namespace.conf.erb"
        owner user
        group user
        mode 0644
        ignore_failure true
        cookbook "logstash"
        variables(:output_namespace_topic => "rb_monitor_post",
                  :namespaces => namespaces
        )
        notifies :restart, "service[logstash]", :delayed
      end
    end

    # Redfish pipeline
    if is_manager || is_proxy
      template "#{pipelines_dir}/redfish/00_input.conf" do
        source "redfish_input.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        variables(:device_nodes => device_nodes,
                  :monitors => monitors_dg["monitors"]
        )
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/redfish/01_normalize.conf" do
        source "redfish_normalize.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/redfish/02_enrichment.conf" do
        source "redfish_enrichment.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        variables(:device_nodes => device_nodes)
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/redfish/99_output.conf" do
          source "output_kafka.conf.erb"
          owner user
          group user
          mode 0644
          ignore_failure true
          cookbook "logstash"
          retries 2
          variables(:output_topic => "rb_monitor")
          notifies :restart, "service[logstash]", :delayed
      end
    end

    # IPS pipeline
    if is_manager || is_sensor
      template "#{pipelines_dir}/ips/00_input.conf" do
        source "ips_input.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        variables(:input_topics => ["rb_event"])
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/ips/10_ips.conf" do
        source "ips_ips.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        variables(:reputation_managers => ["rb-reputation"]) # Idk if this shit works, may need to remove this line
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/ips/99_output.conf" do
        source "ips_output.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        variables(:output_topic => "rb_malware_post",
        :namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end

    # Intrusion pipeline
    if is_manager || is_sensor
      template "#{pipelines_dir}/intrusion/00_input.conf" do #TODO add pipelines for ips and intrusion
        source "intrusion_input.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        cookbook "logstash"
        notifies :restart, "service[logstash]", :delayed
      end

      template "#{pipelines_dir}/intrusion/01_intrusion.conf" do
        source "intrusion_intrusion.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        notifies :restart, "service[logstash]", :delayed
        action :delete if (logstash_settings and logstash_settings["intrusion"] and !logstash_settings["intrusion"]["multienrichment"]) # Idk wtf to do with this
      end
    

      template "#{pipelines_dir}/intrusion/02_geoenrich.conf" do
        source "intrusion_geoenrich.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        notifies :restart, "service[logstash]", :delayed
        action :delete if (logstash_settings and logstash_settings["intrusion"] and logstash_settings["intrusion"]["geoip"] and logstash_settings["intrusion"]["geoip"] == "0")
      end

      template "#{pipelines_dir}/intrusion/03_macvendor.conf" do
        source "intrusion_macvendor.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        notifies :restart, "service[logstash]", :delayed
        action :delete if (logstash_settings and logstash_settings["intrusion"] and logstash_settings["intrusion"]["macvendor"] and logstash_settings["intrusion"]["macvendor"] == "0")
      end
    
      template "#{pipelines_dir}/intrusion/04_darklist.conf" do
        source "intrusion_darklist.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        notifies :restart, "service[logstash]", :delayed
        action :delete if (logstash_settings and logstash_settings["intrusion"] and logstash_settings["intrusion"]["darklist"] and logstash_settings["intrusion"]["darklist"] == "0")
      end
    
      template "#{pipelines_dir}/intrusion/98_encode.conf" do
        source "intrusion_encode.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        notifies :restart, "service[logstash]", :delayed
      end
      
      template "#{pipelines_dir}/intrusion/99_output.conf" do
        source "intrusion_output.conf.erb"
        owner "root"
        owner "root"
        mode 0644
        retries 2
        variables(:namespaces => namespaces)
        notifies :restart, "service[logstash]", :delayed
      end
  
    # End of pipelines

    #logstash rules
    if is_manager
      directory "#{pipelines_dir}/vault/patterns" do
        owner "root"
        group "root"
        mode 0755
        action :create
      end

      directory "#{pipelines_dir}/bulkstats/patterns" do
        owner "root"
        group "root"
        mode 0755
        action :create
      end

      Dir.foreach("/share/logstash-rules") do |f|
        next if f == '.' or f == '..'
        link "#{pipelines_dir}/vault/patterns/#{f}" do
          to "/share/logstash-rules/#{f}"
        end
      end
    end

    #bulkstats
    directory "/etc/bulkstats" do
      owner "root"
      group "root"
      mode 0777
      action :create
    end

    directory "/etc/bulkstats/data" do
      owner "root"
      group "root"
      mode 0777
      action :create
    end

    # Make subdirectories for sftp
    sensors_uuid_with_monitors = []
    device_nodes.each do |dnode|
      #TODO: Simplify that double if, maybe some bools don't need to be checked anymore
      #TODO: move is_proxy outside
      next if !dnode["redborder"]["parent_id"].nil? and !is_proxy
      if !dnode[:ipaddress].nil? and !dnode["redborder"].nil?
        directories_to_make = []
        dnode["redborder"]["monitors"].each do |monitor|
          directories_to_make |= [monitor["bulkstats_schema_id"]] if monitor["bulkstats_schema_id"]
        end
        # Make the parent directory
        if directories_to_make.count > 0
          sensors_uuid_with_monitors.push(dnode["redborder"][:sensor_uuid])
          directory "/etc/bulkstats/data/#{dnode["redborder"][:sensor_uuid].gsub("-","")}" do
            owner "root"
            group "root"
            mode 0777
            action :create
          end
        end

        # Make the subdirectories
        directories_to_make.each do |dir|
          directory "/etc/bulkstats/data/#{dnode["redborder"][:sensor_uuid].gsub("-","")}/#{dir}" do
            owner "root"
            group "root"
            mode 0777
            action :create
          end
        end
      end
    end

    activate_logstash, has_bulkstats_monitors, has_redfish_monitors = check_proxy_monitors(device_nodes)      #TODO Deprecated?
    node.normal["redborder"]["pending_bulkstats_changes"] = 0 if node["redborder"]["pending_bulkstats_changes"].nil?

    if is_proxy
      execute "rb_get_bulkstats_columns" do
        ignore_failure true
        command "/usr/lib/redborder/scripts/rb_get_bulkstats_columns.rb"
        notifies :run, "ruby_block[update_pending_bulkstats_changes]", :immediately
        only_if { (has_bulkstats_monitors and ( node["redborder"]["pending_bulkstats_changes"]>0) or !::File.exist?("/share/bulkstats.tar.gz")) }
      end

      ruby_block "update_pending_bulkstats_changes" do
        block do
          if node["redborder"]["pending_bulkstats_changes"]>0
            node.normal["redborder"]["pending_bulkstats_changes"] = (node.normal["redborder"]["pending_bulkstats_changes"].to_i-1)
          else
            node.normal["redborder"]["pending_bulkstats_changes"] = 0
          end
        end
        action :nothing
        notifies :restart, "service[logstash]", :delayed if activate_logstash
      end
    end

    # end of bulkstats

    service "logstash" do
      service_name "logstash"
      ignore_failure true
      supports :status => true, :reload => true, :restart => true, :enable => true
      action [:start, :enable] if is_manager or (activate_logstash and is_proxy)
      action [:stop, :disable] if !activate_logstash and is_proxy
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

    directory "/etc/logstash" do
      recursive true
      action :delete
    end

    dnf_package "logstash" do
      action :remove
    end

    dnf_package "logstash-rules" do
      action :remove
    end

    dnf_package "redborder-logstash-plugins" do
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

      node.normal["logstash"]["registered"] = true
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

      node.normal["logstash"]["registered"] = false
      Chef::Log.info("Logstash service has been deregistered from consul")
    end
  rescue => e
    Chef::Log.error(e.message)
  end
end
