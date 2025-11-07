# Cookbook:: logstash
# Provider:: config

include Logstash::Helper

action :add do
  begin
    user = new_resource.user
    logstash_dir = new_resource.logstash_dir
    pipelines_dir = new_resource.pipelines_dir
    flow_nodes = new_resource.flow_nodes
    proxy_nodes = new_resource.proxy_nodes
    device_nodes = new_resource.device_nodes
    vault_nodes = new_resource.vault_nodes
    scanner_nodes = new_resource.scanner_nodes
    ips_nodes = new_resource.ips_nodes
    mobility_nodes = new_resource.mobility_nodes
    namespaces = new_resource.namespaces
    memcached_server = new_resource.memcached_server
    mac_vendors = new_resource.mac_vendors
    logstash_pipelines = new_resource.logstash_pipelines
    split_traffic_logstash = new_resource.split_traffic_logstash
    split_intrusion_logstash = new_resource.split_intrusion_logstash
    intrusion_incidents_priority_filter = new_resource.intrusion_incidents_priority_filter
    vault_incidents_priority_filter = new_resource.vault_incidents_priority_filter
    malware_score_threshold = new_resource.malware_score_threshold
    malware_incidents_priority = new_resource.malware_incidents_priority
    is_proxy = is_proxy?
    is_manager = is_manager?
    flow_nodes_without_proxy = new_resource.flow_nodes_without_proxy
    flow_nodes_with_proxy = new_resource.flow_nodes_with_proxy
    redis_hosts = new_resource.redis_hosts
    redis_port = new_resource.redis_port
    redis_secrets = new_resource.redis_secrets
    redis_password = redis_secrets['pass'] unless redis_secrets.empty?
    s3_malware_secrets = new_resource.s3_malware_secrets
    cdomain = new_resource.cdomain

    memcached_servers = node['redborder']['memcached']['hosts']

    begin
      sensors_data = YAML.load(::File.open('/etc/logstash/sensors_data.yml'))
      default_sensor = YAML.load(::File.open('/etc/logstash/default_sensor.yml'))
    rescue
      sensors_data = { 'sensors' => {} }
      default_sensor = { 'sensor' => {} }
    end

    dnf_package 'logstash-rules' do
      only_if { is_manager }
      action :upgrade
    end

    dnf_package 'logstash' do
      action :upgrade
    end

    dnf_package 'redborder-logstash-plugins' do
      action :upgrade
    end

    execute 'create_user' do
      command "/usr/sbin/useradd -r #{user}"
      ignore_failure true
      not_if "getent passwd #{user}"
    end

    group 'virusgroup' do
      append true
      members ['logstash']
      action :manage
      only_if 'getent group virusgroup'
    end

    begin
      logstash_hash_item = data_bag_item('passwords', 'vault')
    rescue
      logstash_hash_item = { hash_key: node['redborder']['rsyslog']['hash_key'],
                             hash_function: node['redborder']['rsyslog']['hash_function'] }
    end

    begin
      monitors_dg = data_bag_item('rBglobal', 'monitors')
    rescue
      monitors_dg = {}
    end

    begin
      db_redborder_secrets = data_bag_item('passwords', 'db_redborder')
    rescue
      db_redborder_secrets = {}
    end

    unless db_redborder_secrets.empty?
      database_name = db_redborder_secrets['database']
      username = db_redborder_secrets['username']
      password = db_redborder_secrets['pass']
      port = db_redborder_secrets['port']
      host = db_redborder_secrets['hostname']
    end

    %W(#{logstash_dir} #{pipelines_dir}).each do |dir|
      directory dir do
        owner user
        group user
        mode '0755'
        action :create
      end
    end

    pipelines = []
    if is_manager
      pipelines = %w(sflow netflow vault scanner nmsp location mobility meraki apstate radius rbwindow bulkstats redfish monitor intrusion druid-metrics malware)
    elsif is_proxy
      pipelines = %w(bulkstats redfish)
    end

    pipelines.each do |pipeline|
      directory "#{pipelines_dir}/#{pipeline}" do
        owner user
        group user
        mode '0755'
        action :create
      end
    end

    template "#{logstash_dir}/logstash.yml" do
      source 'logstash.yml.erb'
      owner user
      group user
      mode '0644'
      ignore_failure true
      cookbook 'logstash'
      variables(user: user)
      notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
    end

    template "#{logstash_dir}/pipelines.yml" do
      source 'pipelines.yml.erb'
      owner user
      group user
      mode '0644'
      ignore_failure true
      cookbook 'logstash'
      variables(is_manager: is_manager, is_proxy: is_proxy, pipelines: logstash_pipelines)
      notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
    end

    template '/etc/logrotate.d/logstash' do
      source 'logstash_log_rotate.erb'
      owner 'root'
      group 'root'
      mode '0644'
      retries 2
      cookbook 'logstash'
    end

    # Vault pipeline
    if is_manager
      template "#{pipelines_dir}/vault/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_vault'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/01_generic.conf" do
        source 'vault_generic.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(hash_key: logstash_hash_item[:hash_key], hash_function: logstash_hash_item[:hash_function])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/02_sshd.conf" do
        source 'vault_sshd.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/03_iptables.conf" do
        source 'vault_iptables.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/04_nginx.conf" do
        source 'vault_nginx.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/05_dnsmasq.conf" do
        source 'vault_dnsmasq.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # We dont need this file anymore as is parsed by rsyslog
      file "#{pipelines_dir}/vault/06_alarms.conf" do
        action :delete
      end

      # Renamed so we clean the old file
      file "#{pipelines_dir}/vault/06_addfields.conf" do
        action :delete
      end

      template "#{pipelines_dir}/vault/07_addfields.conf" do
        source 'vault_addfields.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # Renamed so we clean the old file
      file "#{pipelines_dir}/vault/07_incident_enrichment.conf" do
        action :delete
      end

      template "#{pipelines_dir}/vault/08_incident_enrichment.conf" do
        source 'vault_incident_enrichment.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(vault_incidents_priority_filter: vault_incidents_priority_filter,
                  redis_hosts: redis_hosts,
                  redis_port: redis_port,
                  redis_password: redis_password)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/09_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: vault_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/10_threat_intelligence.conf" do
        source 'vault_threat_intelligence.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_servers: memcached_servers, vault_nodes: vault_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/vault/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_vault_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # sflow pipeline
    if is_manager
      template "#{pipelines_dir}/sflow/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['sflow'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/sflow/01_tagging.conf" do
        source 'sflow_tagging.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(flow_nodes: flow_nodes, proxy_nodes: proxy_nodes, split_traffic_logstash: split_traffic_logstash)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/sflow/02_normalization.conf" do
        source 'sflow_normalization.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(split_traffic_logstash: split_traffic_logstash)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/sflow/03_enrichment.conf" do
        source 'sflow_enrichment.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(split_traffic_logstash: split_traffic_logstash, flow_nodes_without_proxy: flow_nodes_without_proxy, flow_nodes_with_proxy: flow_nodes_with_proxy)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/sflow/04_field_conversion.conf" do
        source 'sflow_field_conversion.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/sflow/99_output.conf" do
        source 'output_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(input_topics: ['sflow'],
                  output_topic: 'rb_flow')
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # netflow pipeline
    if is_manager
      template "#{pipelines_dir}/netflow/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_flow'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/01_macscrambling.conf" do
        source 'netflow_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/02_geoenrich.conf" do
        source 'netflow_geoenrich.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/03_macvendor.conf" do
        source 'netflow_macvendor.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server,
                  mac_vendors: mac_vendors)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # Clean the file
      file '/etc/logstash/pipelines/netflow/04_darklist.conf' do
        action :delete
        only_if { ::File.exist?('/etc/logstash/pipelines/netflow/04_darklist.conf') }
      end

      template "#{pipelines_dir}/netflow/05_threat_intelligence.conf" do
        source 'netflow_threat_intelligence.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_servers: memcached_servers, flow_nodes: flow_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/06_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: flow_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/08_assets.conf" do
        source 'netflow_assets.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/85_discard_events.conf" do
        source 'netflow_discard_events.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/90_splitflow.conf" do
        source 'netflow_splitflow.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/91_rename.conf" do
        source 'netflow_rename.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/netflow/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_flow_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # scanner pipeline
    if is_manager
      template "#{pipelines_dir}/scanner/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_scanner'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/scanner/01_normalization.conf" do
        source 'scanner_normalization.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/scanner/02_postgrescve.conf" do
        source 'scanner_postgrescve.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(username: username, password: password, port: port, host: host, database_name: database_name)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/scanner/03_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: scanner_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/scanner/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_scanner_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # NMSP pipeline
    if is_manager
      template "#{pipelines_dir}/nmsp/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_nmsp'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/nmsp/01_macscrambling.conf" do
        source 'nmsp_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/nmsp/03_nmsp.conf" do
        source 'nmsp_removefields.conf.erb'
        owner user
        group user
        mode '0644'
        retries 2
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/nmsp/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_topics: ['rb_location'],
                  output_namespace_topic: 'rb_wireless',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Location pipeline
    if is_manager
      template "#{pipelines_dir}/location/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_loc'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/location/01_macscrambling.conf" do
        source 'location_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/location/02_macvendor.conf" do
        source 'netflow_macvendor.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(mac_vendors: mac_vendors)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/location/10_location.conf" do
        source 'location_location.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/location/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_topics: ['rb_location'],
                  output_namespace_topic: 'rb_wireless',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Mobility pipeline
    if is_manager
      template "#{pipelines_dir}/mobility/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_location'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/mobility/01_mobility.conf" do
        source 'mobility_removefields.conf.erb'
        owner user
        group user
        mode '0644'
        retries 2
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/mobility/02_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: mobility_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/mobility/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_loc_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # MERAKI pipeline
    if is_manager
      template "#{pipelines_dir}/meraki/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['sflow'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/meraki/01_macscrambling.conf" do
        source 'meraki_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/meraki/03_meraki.conf" do
        source 'meraki_removefields.conf.erb'
        owner user
        group user
        mode '0644'
        retries 2
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/meraki/99_output.conf" do
        source 'output_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_topic: 'rb_location')
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # freeradius pipeline
    if is_manager
      template "#{pipelines_dir}/radius/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_radius'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/radius/01_macscrambling.conf" do
        source 'radius_macscrambling.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/radius/03_radius.conf" do
        source 'radius_radius.conf.erb'
        owner 'root'
        owner 'root'
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        retries 2
        variables(memcached_server: memcached_server)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/radius/99_output.conf" do
        source 'output_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_topic: 'rb_location')
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # apstate pipeline
    if is_manager
      template "#{pipelines_dir}/apstate/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_state'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/apstate/01_apstate.conf" do
        source 'apstate_apstate.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/apstate/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_state_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Rbwindow pipelines
    if is_manager
      template "#{pipelines_dir}/rbwindow/00_input.conf" do
        source 'rbwindow_00_input.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        retries 2
        variables(memcached_server: memcached_server, database_name: database_name, host: host,
                  password: password, user: username, port: port)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/rbwindow/99_output.conf" do
        source 'rbwindow_99_output.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Bulskstats pipeline
    if is_manager || is_proxy
      template "#{pipelines_dir}/bulkstats/00_input.conf" do
        source 'bulkstats_input.conf.erb'
        owner user
        owner user
        mode '0644'
        cookbook 'logstash'
        retries 2
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/bulkstats/01_bulkstats.conf" do
        source 'bulkstats_bulkstats.conf.erb'
        owner user
        owner user
        mode '0644'
        cookbook 'logstash'
        retries 2
        variables(device_nodes: device_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/bulkstats/02_enrichment.conf" do
        source 'bulkstats_enrichment.conf.erb'
        owner user
        owner user
        mode '0644'
        cookbook 'logstash'
        retries 2
        variables(device_nodes: device_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/bulkstats/99_output.conf" do
        source 'output_kafka.conf.erb'
        owner user
        owner user
        mode '0644'
        cookbook 'logstash'
        retries 2
        variables(output_topic: 'rb_monitor')
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Monitor pipeline
    if is_manager
      template "#{pipelines_dir}/monitor/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_monitor'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/monitor/01_monitor.conf" do
        source 'monitor_removefields.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/monitor/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_monitor_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Intrusion pipeline
    if is_manager
      template "#{pipelines_dir}/intrusion/00_input.conf" do
        source 'input_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(topics: ['rb_event'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/01_intrusion.conf" do
        source 'intrusion_intrusion.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/02_geoenrich.conf" do
        source 'intrusion_geoenrich.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/03_macvendor.conf" do
        source 'intrusion_macvendor.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_server: memcached_server,
                  mac_vendors: mac_vendors)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # Clean the file
      file '/etc/logstash/pipelines/intrusion/04_darklist.conf' do
        action :delete
        only_if { ::File.exist?('/etc/logstash/pipelines/intrusion/04_darklist.conf') }
      end

      # This is related with this task
      # https://redmine.redborder.lan/issues/18682
      # We should improve it but do not delete it
      template "#{pipelines_dir}/intrusion/05_intrusion_tagging.conf" do
        source 'intrusion_tagging.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(sensors: sensors_data['sensors'], default_sensor: default_sensor['default_sensor'], split_intrusion_logstash: split_intrusion_logstash)
        notifies :restart, 'service[logstash]', :delayed
      end

      template "#{pipelines_dir}/intrusion/06_incident_enrichment.conf" do
        source 'intrusion_incident_enrichment.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(intrusion_incidents_priority_filter: intrusion_incidents_priority_filter,
                  redis_hosts: redis_hosts,
                  redis_port: redis_port,
                  redis_password: redis_password)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/07_threat_intelligence.conf" do
        source 'intrusion_threat_intelligence.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(memcached_servers: memcached_servers, ips_nodes: ips_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/08_check_license.conf" do
        source 'check_license.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(nodes: ips_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/98_encode.conf" do
        source 'intrusion_encode.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/intrusion/99_output.conf" do
        source 'output_kafka_namespace.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(output_namespace_topic: 'rb_event_post',
                  namespaces: namespaces)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Druid metrics pipeline
    if is_manager
      template "#{pipelines_dir}/druid-metrics/00_input.conf" do
        source 'druid_metrics_00_input.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/druid-metrics/99_output.conf" do
        source 'druid_metrics_99_output.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Redfish pipeline
    if is_manager || is_proxy
      template "#{pipelines_dir}/redfish/00_input.conf" do
        source 'redfish_input.conf.erb'
        owner 'root'
        owner 'root'
        mode '0644'
        retries 2
        cookbook 'logstash'
        variables(device_nodes: device_nodes,
                  monitors: monitors_dg['monitors'])
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/redfish/01_normalize.conf" do
        source 'redfish_normalize.conf.erb'
        owner 'root'
        owner 'root'
        mode '0644'
        retries 2
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/redfish/02_enrichment.conf" do
        source 'redfish_enrichment.conf.erb'
        owner 'root'
        owner 'root'
        mode '0644'
        retries 2
        cookbook 'logstash'
        variables(device_nodes: device_nodes)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/redfish/99_output.conf" do
        source 'output_kafka.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        retries 2
        variables(output_topic: 'rb_monitor')
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # Malware pipeline
    if is_manager
      execute 'add_logstash_to_malware_group' do
        command "usermod -aG malware #{user}"
        only_if 'getent group malware'
        not_if "id -nG #{user} | grep -qw malware"
      end

      directory '/usr/share/logstash/yara_rules' do
        owner 'webui'
        group 'webui'
        mode '0755'
        action :create
        only_if 'getent passwd webui'
      end

      file '/var/log/logstash/logstash-malware-sincedb.log' do
        owner user
        group user
        mode '0644'
        action :create
      end

      # Malware Weights file
      # Will be read from logstash-filter-aerospike-malware-score
      template '/usr/share/logstash/weights.yml' do
        source 'malware_weights.yml.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/malware/00_input.conf" do
        source 'malware_00_input.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/malware/01_normalize.conf" do
        source 'malware_01_normalize.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # Virus Total
      if node['redborder']['manager']['loaders'] && node['redborder']['manager']['loaders']['virustotal_api_key'] &&
         !node['redborder']['manager']['loaders']['virustotal_api_key'].empty?
        template "#{pipelines_dir}/malware/10_virustotal.conf" do
          source 'malware_10_virustotal.conf.erb'
          owner user
          group user
          mode '0644'
          ignore_failure true
          cookbook 'logstash'
          variables(apikey: node['redborder']['manager']['loaders']['virustotal_api_key'],
                    access_key_id: s3_malware_secrets['s3_malware_access_key_id'],
                    secret_access_key: s3_malware_secrets['s3_malware_secret_key_id'],
                    cdomain: cdomain)
          notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
        end
      elsif ::File.exist?("#{pipelines_dir}/malware/10_virustotal.conf")
        file "#{pipelines_dir}/malware/10_virustotal.conf" do
          action :delete
        end
      end

      # MetaDefender
      if node['redborder']['loaders'] && node['redborder']['loaders']['metadefender_api_key'] &&
         !node['redborder']['loaders']['metadefender_api_key'].empty? && !s3_malware_secrets['s3_malware_access_key_id'].nil? &&
         !s3_malware_secrets['s3_malware_access_key_id'].empty? && !s3_malware_secrets['s3_malware_secret_key_id'].nil? && !s3_malware_secrets['s3_malware_secret_key_id'].empty?
        template "#{pipelines_dir}/malware/20_metadefender.conf" do
          source 'malware_20_metadefender.conf.erb'
          owner user
          group user
          mode '0644'
          ignore_failure true
          cookbook 'logstash'
          variables(apikey: node['redborder']['loaders']['metadefender_api_key'],
                    access_key_id: s3_malware_secrets['s3_malware_access_key_id'],
                    secret_access_key: s3_malware_secrets['s3_malware_secret_key_id'],
                    cdomain: cdomain)
          notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
        end
      elsif ::File.exist?("#{pipelines_dir}/malware/20_metadefender.conf")
        file "#{pipelines_dir}/malware/20_metadefender.conf" do
          action :delete
        end
      end

      # Clamscan
      template "#{pipelines_dir}/malware/30_clamscan.conf" do
        source 'malware_30_clamscan.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(access_key_id: s3_malware_secrets['s3_malware_access_key_id'],
                  secret_access_key: s3_malware_secrets['s3_malware_secret_key_id'],
                  cdomain: cdomain)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      # Yara
      # template "#{pipelines_dir}/malware/40_yara.conf" do
      #   source 'malware_40_yara.conf.erb'
      #   owner user
      #   group user
      #   mode '0644'
      #   ignore_failure true
      #   cookbook 'logstash'
      #   variables(access_key_id: s3_malware_secrets['s3_malware_access_key_id'],
      #             secret_access_key: s3_malware_secrets['s3_malware_secret_key_id'],
      #             cdomain: cdomain)
      #   notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      # end

      # Fuzzy
      # TO DO: Integrate Fuzzy
      # template "#{pipelines_dir}/malware/50_fuzzy.conf" do
      #   source 'malware_50_fuzzy.conf.erb'
      #   owner user
      #   group user
      #   mode '0644
      #   ignore_failure true
      #   cookbook 'logstash''
      #   variables(access_key_id: s3_malware_secrets["s3_malware_access_key_id"],
      #             secret_access_key: s3_malware_secrets["s3_malware_secret_key_id"],
      #             cdomain: cdomain)
      #   notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      # end

      # CAPEv2
      # TO DO: Integrate CAPEv2
      # if node['redborder']['loaders'] && managers_per_service['cape_api'] && !managers_per_service['cape_api'].empty?
      #   template "#{pipelines_dir}/malware/60_cape.conf" do
      #     source 'malware_60_cape.conf.erb'
      #     owner user
      #     group user
      #     mode '0644'
      #     ignore_failure true
      #     cookbook 'logstash'
      #     notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      #   end
      # elsif File.exist?("#{pipelines_dir}/malware/60_cape.conf")
      #   file "#{pipelines_dir}/malware/60_cape.conf" do
      #     action :delete
      #   end
      # end

      template "#{pipelines_dir}/malware/97_incident_enrichment.conf" do
        source 'malware_incident_enrichment.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        variables(malware_score_threshold: malware_score_threshold,
                  malware_incidents_priority: malware_incidents_priority,
                  redis_hosts: redis_hosts,
                  redis_port: redis_port,
                  redis_password: redis_password)
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/malware/98_clean_input_files.conf" do
        source 'malware_98_clean_input_files.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end

      template "#{pipelines_dir}/malware/99_output.conf" do
        source 'malware_99_output.conf.erb'
        owner user
        group user
        mode '0644'
        ignore_failure true
        cookbook 'logstash'
        notifies :restart, 'service[logstash]', :delayed unless node['redborder']['leader_configuring']
      end
    end

    # End of pipelines

    # logstash rules
    if is_manager
      directory "#{pipelines_dir}/vault/patterns" do
        owner 'root'
        group 'root'
        mode '0755'
        action :create
      end

      directory "#{pipelines_dir}/bulkstats/patterns" do
        owner 'root'
        group 'root'
        mode '0755'
        action :create
      end

      Dir.foreach('/share/logstash-rules') do |f|
        next if f == '.' || f == '..'
        link "#{pipelines_dir}/vault/patterns/#{f}" do
          to "/share/logstash-rules/#{f}"
        end
      end
    end

    # bulkstats
    directory '/etc/bulkstats' do
      owner 'root'
      group 'root'
      mode '0777'
      action :create
    end

    directory '/etc/bulkstats/data' do
      owner 'root'
      group 'root'
      mode '0777'
      action :create
    end

    # Make subdirectories for sftp
    sensors_uuid_with_monitors = []
    device_nodes.each do |dnode|
      # TODO: Simplify that double if, maybe some bools don't need to be checked anymore
      # TODO: move is_proxy outside
      next if !dnode['redborder']['parent_id'].nil? && !is_proxy

      next unless dnode[:ipaddress] && dnode['redborder']

      directories_to_make = []
      dnode['redborder']['monitors'].each do |monitor|
        directories_to_make |= [monitor['bulkstats_schema_id']] if monitor['bulkstats_schema_id']
      end

      # Make the parent directory
      if directories_to_make.count > 0
        sensors_uuid_with_monitors.push(dnode['redborder'][:sensor_uuid])
        directory "/etc/bulkstats/data/#{dnode['redborder'][:sensor_uuid].gsub('-', '')}" do
          owner 'root'
          group 'root'
          mode '0777'
          action :create
        end
      end

      # Make the subdirectories
      directories_to_make.each do |dir|
        directory "/etc/bulkstats/data/#{dnode['redborder'][:sensor_uuid].gsub('-', '')}/#{dir}" do
          owner 'root'
          group 'root'
          mode '0777'
          action :create
        end
      end
    end

    # TODO: Check if this is deprecated
    has_bulkstats_monitors = bulkstats_monitors?(device_nodes)
    has_redfish_monitors = redfish_monitors?(device_nodes)

    activate_logstash = has_bulkstats_monitors || has_redfish_monitors

    if node['redborder']['pending_bulkstats_changes'].nil?
      node.normal['redborder']['pending_bulkstats_changes'] = 0
    end

    if is_proxy
      execute 'rb_get_bulkstats_columns' do
        ignore_failure true
        command '/usr/lib/redborder/scripts/rb_get_bulkstats_columns.rb'
        notifies :run, 'ruby_block[update_pending_bulkstats_changes]', :immediately
        only_if { (has_bulkstats_monitors && (node['redborder']['pending_bulkstats_changes'] > 0) || !::File.exist?('/share/bulkstats.tar.gz')) }
      end

      ruby_block 'update_pending_bulkstats_changes' do
        block do
          node.normal['redborder']['pending_bulkstats_changes'] = (node['redborder']['pending_bulkstats_changes'] > 0) ? (node.normal['redborder']['pending_bulkstats_changes'].to_i - 1) : 0
        end
        action :nothing
        notifies :restart, 'service[logstash]', :delayed if activate_logstash
      end
    end

    if is_manager
      directory '/etc/assets' do
        owner 'root'
        group 'root'
        mode '0777'
        action :create
      end

      # This script will generated the YAML file needed to enrich the asset type into the events
      execute 'rb_create_asset_type_yaml' do
        ignore_failure true
        command '/usr/lib/redborder/bin/rb_create_asset_type_yaml.sh /etc/assets/mac_to_asset_type.yaml'
        action :run
        not_if { node['redborder']['leader_configuring'] }
      end
    end

    service 'logstash' do
      service_name 'logstash'
      ignore_failure true
      supports status: true, reload: true, restart: true, enable: true, stop: true, start: true
      if is_manager
        if node['redborder']['leader_configuring']
          action [:enable, :stop]
        else
          action [:enable, :start]
        end
      elsif activate_logstash # is_proxy
        action [:enable, :start]
      else
        action [:stop, :disable]
      end
    end

    Chef::Log.info('Logstash cookbook has been processed')
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :remove do
  begin
    service 'logstash' do
      service_name 'logstash'
      ignore_failure true
      supports status: true, enable: true
      action [:stop, :disable]
    end

    directory '/etc/logstash' do
      recursive true
      action :delete
    end

    file '/etc/logrotate.d/logstash' do
      action :delete
    end

    dnf_package 'logstash' do
      action :remove
    end

    dnf_package 'logstash-rules' do
      action :remove
    end

    dnf_package 'redborder-logstash-plugins' do
      action :remove
    end

    Chef::Log.info('Logstash cookbook has been processed')
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :register do
  begin
    ipaddress_sync = new_resource.ipaddress_sync
    unless node['logstash']['registered']
      query = {}
      query['ID'] = "logstash-#{node['hostname']}"
      query['Name'] = 'logstash'
      query['Address'] = ipaddress_sync
      query['Port'] = 5000
      json_query = Chef::JSONCompat.to_json(query)

      execute 'Register service in consul' do
        command "curl -X PUT http://localhost:8500/v1/agent/service/register -d '#{json_query}' &>/dev/null"
        action :nothing
      end.run_action(:run)

      node.normal['logstash']['registered'] = true
      Chef::Log.info('Logstash service has been registered to consul')
    end
  rescue => e
    Chef::Log.error(e.message)
  end
end

action :deregister do
  begin
    if node['logstash']['registered']
      execute 'Deregister service in consul' do
        command "curl -X PUT http://localhost:8500/v1/agent/service/deregister/logstash-#{node['hostname']} &>/dev/null"
        action :nothing
      end.run_action(:run)

      node.normal['logstash']['registered'] = false
      Chef::Log.info('Logstash service has been deregistered from consul')
    end
  rescue => e
    Chef::Log.error(e.message)
  end
end
