cookbook-logstash CHANGELOG
===============

## 8.1.1

  - Rafa Gómez
    - [ec1b7b4] Improvement/#20536 Migrate logstash log rotate from cookbook-rb-manager (#109)

## 8.1.0

  - Miguel Negrón
    - [58b145a] Dont create asset type if node still configuring
    - [af09bbf] Make dynamic file path
    - [110bf70] Rename files
    - [fa0ecb4] Add template

## 8.0.1

  - nilsver
    - [9f653e0] remove flush cache

## 8.0.0

  - vimesa && manegron
    - [05185f8] Merge pull request #96 from redBorder/feature/#20408_update_ti
    - [f176e47] Remove commas between sensors
    - [317ba81] Remove mapping uri with url for intrusion ti
    - [9932f05] Update ti
    - [3a41bef] Fix syntax error
    - [15856d6] Update threshold
    - [1ac70fa] Update ti
    - [52388c3] Fix syntax error
    - [38ec2eb] Add intrusion nodes
    - [973c149] change key_mapper by indicators_types
    - [655abee] Update ti
    - [49a4b48] Update ti
    - [fe05a84] Merge branch 'feature/#20408_update_ti' of github.com:redBorder/cookbook-logstash into feature/#20408_update_ti
    - [8cd1c2b] Add condition when policy_id is 0
    - [84cb313] Fix intrusion threat intelligence pipeline
    - [eea3565] Modify template
    - [896b852] Add intrusion and vault threat intelligence pipeline
    - [a92a276] Rename intrusion_nodes to ips_nodes
    - [ec53bb8] Merge branch 'master' into feature/#20408_update_ti
    - [6e5ba69] Delete the old file if it exists
    - [d07d32a] Add threshold
    - [110be09] Merge branch 'master' into feature/#20408_flow_reputations
    - [f1d1b36] Modify template
    - [37b3653] Add flow reputation
    - [28b2566] Add reputations policies
    - [05185f8] Merge pull request #96 from redBorder/feature/#20408_update_ti
    - [f176e47] Remove commas between sensors
    - [317ba81] Remove mapping uri with url for intrusion ti
    - [1ea901b] Remove empty file
    - [c5b1556] Merge branch 'master' into feature/#20408_update_ti
    - [9932f05] Update ti
    - [3a41bef] Fix syntax error
    - [15856d6] Update threshold
    - [1ac70fa] Update ti
    - [52388c3] Fix syntax error
    - [38ec2eb] Add intrusion nodes
    - [973c149] change key_mapper by indicators_types
    - [655abee] Update ti
    - [49a4b48] Update ti
    - [07bf824] Fix lint rename sensors_policies

## 7.3.1

  - Pablo Pérez
    - [0947aea] Merge pull request #103 from redBorder/feature/#21708_remove_darklist
  - vimesa
    - [5e054b3] Remove darklist

## 7.3.0

  - Miguel Negrón
    - [6254eaf] Add comment back

## 7.2.0

  - Miguel Negrón
    - [8fb2cf0] Merge pull request #100 from redBorder/improvement/#21553_rename_sensor_blocked_by_discard
    - [1ea1ec9] Rename elements
    - [238703b] Discard events
    - [094ed98] Discard events instead of blocked

## 7.1.0

  - Miguel Negrón
    - [67a7e98] Merge pull request #98 from redBorder/bugfix/#21549_block_sensors_without_sensor_name_uuid
    - [236a605] Update template
    - [b6ef1b6] Add netflow step

## 7.0.0

  - Miguel Negrón
    - [fff8561] Merge pull request #95 from redBorder/feature/#21232_refactor_license_system_ng
  - Rafael Gomez
    - [a7eead6] Refactor check_license configuration to streamline handling of node groups and improve blocked sensor logic
    - [e63952c] Refactor check_license configuration to iterate over node groups for improved handling of blocked sensors
    - [0dfce08] Refactor check_license configuration to handle both Hash and Array types for nodes
    - [9a37a12] Add mobility_nodes attribute to logstash config resource
    - [866c052] Add mobility_nodes attribute to logstash config resource
    - [bf92182] Enhance Kafka output configuration to handle sensor blocking logic for output topics and namespaces
    - [62c4408] Add check_license configuration template for sensor blocking logic
    - [86f0df1] Add default value for 'ips_nodes' attribute in logstash config
    - [3413db4] Remove 'rb_limits' topic from logstash variable configurations
    - [c0fac87] Fix linter: Update variable syntax for topics to use %w() format in logstash config
    - [d43cac6] Refactor variable topic definitions to use %w syntax for linter
    - [3d82218] Add 'rb_limits' topic to multiple logstash variable configurations


## 6.1.4

  - Juan Soto
    - [8847861]  Improvement/#20539 add way to split intrusion with default sensor #90 : Add default sensor for traffic outside organizations

## 6.1.3

  - Rafa Gómez
    - [c81e08e] refactor: update source names in incident enrichment configurations (#92)

## 6.1.2

  - Juan Soto
    - [819cc43] Bugfix/#20011 default magic number is not working (#88)

## 6.1.1

  - nilsver
    - [a0a9c77] check should be reversed
    - [bc111d6] remove splittraffic_check

## 6.1.0

  - David Vanhoucke
    - [51f427d] add vlan normalization

## 6.0.0

  - Miguel Negrón
    - [94bcd8f] Merge pull request #83 from redBorder/bugfix/#19815_fix_splitting_traffic_sflow_pipeline
    - [940b53d] Fix last row
    - [6feffeb] Load interfaces proxy from the role instead of role
  - nilsver
    - [7cd2f65] Release
  - Miguel Álvarez
    - [fcbea79] Add new filters for flow and intrusion (#79)

## 5.0.0

  - Miguel Álvarez
    - [fcbea79] Add new filters for flow and intrusion (#79)

## 4.0.0

  - manegron
    - [bd193fc] remove space
    - [69bb4b7] Dont incident_enrichment if is already enriched
    - [43b5113] Remove alarms from vault pipeline

## 3.3.0

  - Miguel Negrón
    - [040d65c] Fix geoip filter for intrusion pipeline

## 3.2.1

  - Juan Soto
    - [2beed53] Put default direction back
    - [9f3d8c6] Add way to manage three scenearios to tagging

## 3.2.0

  - Pablo Pérez
    - [e92ec9a] Merge pull request #73 from redBorder/bugfix/#19198_vault_priorities_incorrect_values
  - Juan Soto
    - [e42caa4] Feature/#18682 add way to split instrusion (#69)
  - ptorresred
    - [3e65dd8] Redmine bugfix #19198: Change vault default priority filter

## 3.1.0

  - Miguel Negrón
    - [c944474] Merge pull request #71 from redBorder/feature/#18816_Split_Filter_Incident_Priority
  - ptorresred
    - [9d73f72] feature/#18816: Added intrusion variables
    - [ba978a3] feature/#18816: changes to use the splitted incident priority filter

## 3.0.0

  - Miguel Negrón
    - [9354332] Merge pull request #68 from redBorder/improvement/boost_installation_stage_1
    - [4cbf118] Merge pull request #64 from redBorder/feature/#18086_incident_enrichment_vault
    - [1eb9214] Merge pull request #60 from redBorder/feature/18535_send_alarm_to_vault
    - [641aa2e] Merge pull request #62 from redBorder/bugfix/#18728_incidents_priority_filter
    - [bdaefe0] Merge pull request #54 from redBorder/development
    - [0dbb598] Merge pull request #53 from redBorder/development
    - [c3ca31a] Merge pull request #52 from redBorder/development
    - [3efc332] Merge pull request #51 from redBorder/development
  - manegron
    - [9354332] Merge pull request #68 from redBorder/improvement/boost_installation_stage_1
    - [c25be73] Optimize restart calls
    - [1991786] Fix typo
    - [8f784a2] Add missing start in logstash
    - [a54e9b6] Fix lint
    - [d673e43] Change start / stop process
    - [f32b80c] Bump version
    - [270fa47] Add pre and postun to clean the cookbook
    - [fce61f4] Bump version
    - [4cbf118] Merge pull request #64 from redBorder/feature/#18086_incident_enrichment_vault
    - [8a6b586] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [1d0ed2a] Add comments
    - [fd66a8c] Rename 07 to 08
    - [03b4c0b] Fix incident_enrichment call
    - [32deb98] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [a11db39] Bump version
    - [1eb9214] Merge pull request #60 from redBorder/feature/18535_send_alarm_to_vault
    - [f37905c] Fix lint
    - [45335ef] Update vault alarms
    - [861f9ab] clean 06
    - [570bcc2] Add app_name check
    - [d0f4ab4] Merge branch 'development' into feature/18535_send_alarm_to_vault
    - [e8b306d] Bump version
    - [641aa2e] Merge pull request #62 from redBorder/bugfix/#18728_incidents_priority_filter
    - [bdaefe0] Merge pull request #54 from redBorder/development
    - [3778a2a] Release 2.3.3
    - [0dbb598] Merge pull request #53 from redBorder/development
    - [eed18f3] Fix bug consul port as string
    - [c3ca31a] Merge pull request #52 from redBorder/development
    - [564144d] Add Application to sflow
    - [3efc332] Merge pull request #51 from redBorder/development
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step
  - Miguel Negron
    - [fce61f4] Bump version
    - [8a6b586] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [1d0ed2a] Add comments
    - [fd66a8c] Rename 07 to 08
    - [03b4c0b] Fix incident_enrichment call
    - [32deb98] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [a11db39] Bump version
    - [f37905c] Fix lint
    - [45335ef] Update vault alarms
    - [861f9ab] clean 06
    - [570bcc2] Add app_name check
    - [d0f4ab4] Merge branch 'development' into feature/18535_send_alarm_to_vault
    - [e8b306d] Bump version
    - [3778a2a] Release 2.3.3
    - [eed18f3] Fix bug consul port as string
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step
  - JuanSheba
    - [0356641] Release 2.7.0
    - [4a62f5c] Resolve conflicts with development branch
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets
  - Juan Soto
    - [9d98d81] Merge pull request #61 from redBorder/feature/#18681_split_traffic_with_logstash
    - [cf6df39] Merge pull request #57 from redBorder/development
  - vimesa
    - [4ef39a2] Modify incident_fields
    - [e0c2914] Add new pipeline to vault
    - [d936099] Add default value for incidents_priority_filter
  - David Vanhoucke
    - [c64ad3d] add method to activate the split of the traffic through logstash
  - nilsver
    - [8b9a14b] enrich data
  - Rafa Gómez
    - [dbccece] Merge pull request #59 from redBorder/development
    - [034df07] Update CHANGELOG.md
    - [f39a72b] Merge pull request #58 from redBorder/improvement/#18488_modify_logstash-filter-incident-enrichment_to_use_cookbooks
  - Rafael Gomez
    - [dc5ec28] Release 2.4.1
  - Pablo Pérez
    - [39bfe8b] lint
    - [36ebff5] fix syntax
    - [3ef6f83] Added the incident priority filter
    - [b4df9a6] Release 2.3.4
    - [e5d879a] Merge pull request #56 from redBorder/bugfix/#18398_fix_radius_output
    - [ada6b97] Fix
  - Luis Blanco
    - [c9b2ba4] Update CHANGELOG.md
    - [be75f19] auto bump
    - [b24f519] Merge pull request #55 from redBorder/feature/#18174_resolve_differences_between_legacy_and_ng
    - [ceb7e0b] auto lint

## 2.8.1

  - Miguel Negrón
    - [270fa47] Add pre and postun to clean the cookbook

## 2.8.0

  - Miguel Negrón
    - [4cbf118] Merge pull request #64 from redBorder/feature/#18086_incident_enrichment_vault
    - [1eb9214] Merge pull request #60 from redBorder/feature/18535_send_alarm_to_vault
    - [641aa2e] Merge pull request #62 from redBorder/bugfix/#18728_incidents_priority_filter
    - [bdaefe0] Merge pull request #54 from redBorder/development
    - [0dbb598] Merge pull request #53 from redBorder/development
    - [c3ca31a] Merge pull request #52 from redBorder/development
    - [3efc332] Merge pull request #51 from redBorder/development
  - Miguel Negrón
    - [8a6b586] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [1d0ed2a] Add comments
    - [fd66a8c] Rename 07 to 08
    - [03b4c0b] Fix incident_enrichment call
    - [32deb98] Merge branch 'development' into feature/#18086_incident_enrichment_vault
    - [a11db39] Bump version
    - [f37905c] Fix lint
    - [45335ef] Update vault alarms
    - [861f9ab] clean 06
    - [570bcc2] Add app_name check
    - [d0f4ab4] Merge branch 'development' into feature/18535_send_alarm_to_vault
    - [e8b306d] Bump version
    - [3778a2a] Release 2.3.3
    - [eed18f3] Fix bug consul port as string
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step
  - JuanSheba
    - [0356641] Release 2.7.0
    - [4a62f5c] Resolve conflicts with development branch
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets
  - Juan Soto
    - [9d98d81] Merge pull request #61 from redBorder/feature/#18681_split_traffic_with_logstash
    - [cf6df39] Merge pull request #57 from redBorder/development
  - vimesa
    - [4ef39a2] Modify incident_fields
    - [e0c2914] Add new pipeline to vault
    - [d936099] Add default value for incidents_priority_filter
  - David Vanhoucke
    - [c64ad3d] add method to activate the split of the traffic through logstash
  - nilsver
    - [8b9a14b] enrich data
  - Rafa Gómez
    - [dbccece] Merge pull request #59 from redBorder/development
    - [034df07] Update CHANGELOG.md
    - [f39a72b] Merge pull request #58 from redBorder/improvement/#18488_modify_logstash-filter-incident-enrichment_to_use_cookbooks
  - Rafael Gomez
    - [dc5ec28] Release 2.4.1
  - Pablo Pérez
    - [39bfe8b] lint
    - [36ebff5] fix syntax
    - [3ef6f83] Added the incident priority filter
    - [b4df9a6] Release 2.3.4
    - [e5d879a] Merge pull request #56 from redBorder/bugfix/#18398_fix_radius_output
    - [ada6b97] Fix
  - Luis Blanco
    - [c9b2ba4] Update CHANGELOG.md
    - [be75f19] auto bump
    - [b24f519] Merge pull request #55 from redBorder/feature/#18174_resolve_differences_between_legacy_and_ng
    - [ceb7e0b] auto lint

## 2.7.0

  - David Vanhoucke
    - [c64ad3d] add method to activate the split of the traffic through logstash

## 2.6.0

  - Miguel Negrón
    - [1eb9214] Merge pull request #60 from redBorder/feature/18535_send_alarm_to_vault
    - [641aa2e] Merge pull request #62 from redBorder/bugfix/#18728_incidents_priority_filter
    - [bdaefe0] Merge pull request #54 from redBorder/development
    - [0dbb598] Merge pull request #53 from redBorder/development
    - [c3ca31a] Merge pull request #52 from redBorder/development
    - [3efc332] Merge pull request #51 from redBorder/development
  - Miguel Negrón
    - [f37905c] Fix lint
    - [45335ef] Update vault alarms
    - [861f9ab] clean 06
    - [570bcc2] Add app_name check
    - [d0f4ab4] Merge branch 'development' into feature/18535_send_alarm_to_vault
    - [e8b306d] Bump version
    - [3778a2a] Release 2.3.3
    - [eed18f3] Fix bug consul port as string
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step
  - vimesa
    - [d936099] Add default value for incidents_priority_filter
  - nilsver
    - [8b9a14b] enrich data
  - Rafa Gómez
    - [dbccece] Merge pull request #59 from redBorder/development
    - [034df07] Update CHANGELOG.md
    - [f39a72b] Merge pull request #58 from redBorder/improvement/#18488_modify_logstash-filter-incident-enrichment_to_use_cookbooks
  - Rafael Gomez
    - [dc5ec28] Release 2.4.1
  - Pablo Pérez
    - [39bfe8b] lint
    - [36ebff5] fix syntax
    - [3ef6f83] Added the incident priority filter
    - [b4df9a6] Release 2.3.4
    - [e5d879a] Merge pull request #56 from redBorder/bugfix/#18398_fix_radius_output
    - [ada6b97] Fix
  - Juan Soto
    - [cf6df39] Merge pull request #57 from redBorder/development
  - Luis Blanco
    - [c9b2ba4] Update CHANGELOG.md
    - [be75f19] auto bump
    - [b24f519] Merge pull request #55 from redBorder/feature/#18174_resolve_differences_between_legacy_and_ng
    - [ceb7e0b] auto lint
  - JuanSheba
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets

## 2.5.1

  - Miguel Negrón
    - [641aa2e] Merge pull request #62 from redBorder/bugfix/#18728_incidents_priority_filter
    - [bdaefe0] Merge pull request #54 from redBorder/development
    - [0dbb598] Merge pull request #53 from redBorder/development
    - [c3ca31a] Merge pull request #52 from redBorder/development
    - [3efc332] Merge pull request #51 from redBorder/development
  - vimesa
    - [d936099] Add default value for incidents_priority_filter
  - Rafa Gómez
    - [dbccece] Merge pull request #59 from redBorder/development
    - [034df07] Update CHANGELOG.md
    - [f39a72b] Merge pull request #58 from redBorder/improvement/#18488_modify_logstash-filter-incident-enrichment_to_use_cookbooks
  - Rafael Gomez
    - [dc5ec28] Release 2.4.1
  - Pablo Pérez
    - [39bfe8b] lint
    - [36ebff5] fix syntax
    - [3ef6f83] Added the incident priority filter
    - [b4df9a6] Release 2.3.4
    - [e5d879a] Merge pull request #56 from redBorder/bugfix/#18398_fix_radius_output
    - [ada6b97] Fix
  - Juan Soto
    - [cf6df39] Merge pull request #57 from redBorder/development
  - Luis Blanco
    - [c9b2ba4] Update CHANGELOG.md
    - [be75f19] auto bump
    - [b24f519] Merge pull request #55 from redBorder/feature/#18174_resolve_differences_between_legacy_and_ng
    - [ceb7e0b] auto lint
  - JuanSheba
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets
  - Miguel Negrón
    - [3778a2a] Release 2.3.3
    - [eed18f3] Fix bug consul port as string
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step

## 2.4.1

  - Pablo Pérez
    - [3ef6f83] Added the incident priority filter

## 2.4.0

  - JuanSheba
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets
  - Pablo Pérez
    - [ada6b97] Fix Radius output

## 2.3.3

  - Miguel Negrón
    - [eed18f3] Fix bug consul port as string

## 2.3.2

  - Miguel Negrón
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step

## 2.3.1

  - Miguel Negrón
    - [1830258] Add missing default values on sflow normalization step

## 2.3.0

  - Miguel Negrón
    - [cdc7551] Merge pull request #48 from redBorder/feature/incident_response
  - JuanSheba
    - [6fa06e7] Release 2.2.0
  - Juan Soto
    - [0411ec3] Merge pull request #47 from redBorder/feature/#17754_oberservation_id
  - Miguel Negrón
    - [5b77a31] add incident enrichment
  - David Vanhoucke
    - [4a3bc21] add observation id for sflow

## 2.2.0

  - David Vanhoucke
    - [4a3bc21] add observation id for sflow

## 2.1.0

  - Rafael Gomez
    - [b29061a] Feature/#17820 Add intrusion pipeline

## 2.0.5

  - Miguel Negrón
    - [028f051] Improvement/fix lint (#43)

## 2.0.4

  - nilsver
    - [65b6bec] import template logstash from centos6

This file is used to list changes made in each version of the logstash cookbook.

0.0.1
-----
- [jjprieto]
  - COMMIT_REF Initial release of cookbook example

- - -
Check the [Markdown Syntax Guide](http://daringfireball.net/projects/markdown/syntax) for help with Markdown.

The [Github Flavored Markdown page](http://github.github.com/github-flavored-markdown/) describes the differences between markdown on github and standard markdown.
