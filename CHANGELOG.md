cookbook-logstash CHANGELOG
===============

## 2.4.0

  - JuanSheba
    - [48467fe] Remove sflow_rename.conf template and corresponding resource from config.rb.
    - [a233ae8] Refactor Logstash filter to simplify direction-based field renaming, set default values, handle observation_id, and optimize data processing
    - [a622562] Refactor filter to set default 'direction' as 'upstream' and determine 'direction' dynamically based on IP match within homenets
  - Pablo Pérez
    - [ada6b97] Fix Radius output

## 2.3.3

  - Miguel Negron
    - [eed18f3] Fix bug consul port as string

## 2.3.2

  - Miguel Negron
    - [564144d] Add Application to sflow
    - [c4aacf7] Bump version
    - [1830258] Add missing default values on sflow normalization step

## 2.3.1

  - Miguel Negron
    - [1830258] Add missing default values on sflow normalization step

## 2.3.0

  - Miguel Negrón
    - [cdc7551] Merge pull request #48 from redBorder/feature/incident_response
  - JuanSheba
    - [6fa06e7] Release 2.2.0
  - Juan Soto
    - [0411ec3] Merge pull request #47 from redBorder/feature/#17754_oberservation_id
  - Miguel Negron
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
