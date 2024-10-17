cookbook-logstash CHANGELOG
===============

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
