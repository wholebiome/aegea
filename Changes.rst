Changes for v1.5.1 (2016-11-14)
===============================

-  Fogdog mission: add environment placeholder

-  Begin timestamp backport

-  Propagate base AMI metadata in build\_image

Changes for v1.5.0 (2016-11-10)
===============================

-  Implement aegea rds snapshot

-  Only use pager with pretty-printed tables

-  Add Amazon Linux AMI locator

-  Use -w0 for auto col width table formatter

-  aegea zones update: support multiple updates

-  Cosmetic and documentation fixes

Changes for v1.4.0 (2016-11-02)
===============================

-  aegea-build-ami-for-mission: skip make if no Makefile
-  Begin FogDog mission
-  Arvados config support; improve config file handling
-  Don't fail cloud-init on account of expected ssh failure
-  Run ssh-add from aegea launch
-  aegea elb create bugfix
-  Fix ELB behavior when TG is present
-  Simplify arg forwarding in build\_ami

Changes for v1.3.0 (2016-10-20)
===============================

-  Support running core aegea on Ubuntu 14.04 vendored Python

-  Improve freeform cloud-config-data passing

-  Fix pager; introduce --auto-col-width table formatter

-  List security groups in elb listing

-  Break out and begin buildout of aegea ebs subcommand

-  Begin improving rds listings

-  Improve DNS zone repr

-  New protocol to check out local tracking branch in aegea deploy

-  aegea elb create: configurable health check path

-  Key cloud-init files manifest by file path to avoid duplicates

Changes for v1.2.2 (2016-10-08)
===============================

-  ELB provisioning and listing improvements

Changes for v1.2.1 (2016-10-07)
===============================

-  Aegea deploy fixups

Changes for v1.2.0 (2016-10-05)
===============================

-  Online documentation improvements

-  aegea zones: begin ability to edit records from command line

-  Begin support for recursive git clone deploy keys (#4)

-  Pretty-print dicts and lists as json in tables

-  Logic fixes in elb create command

Changes for v1.1.1 (2016-09-27)
===============================

-  Initial support for arvados mission

Changes for v1.1.0 (2016-09-27)
===============================

-  Begin work on missions

-  aegea-deploy-pilot: admit dashes in branch name via service name

-  Fix bug where tweak overwrote config file supplied via environment

-  Online documentation improvements

Changes for v1.0.0 (2016-09-22)
===============================

-  Aegea build\_image renamed to build\_ami
-  Aegea tag, untag
-  Doc improvements
-  Ubuntu 14.04 compatibility and role improvements
-  docker-event-relay reliability improvements
-  Remove snapd from default loadout
-  aegea volumes: display attachment instance names
-  aegea-deploy-pilot: Deploy on SIGUSR1

-  Initial support for flow logs
-  Pretty-print and perform whois lookups for aegea security\_groups
-  aegea ls security\_groups: break out protocol into its own column
-  Print security group rules in aegea ls security\_groups
-  List security groups in aegea ls
-  Print zone ID in aegea zones
-  Aegea deploy reliability improvements: use per-pid queues
-  Aegea launch reliability improvements: Back off on polling the EC2
   API

Changes for v0.9.8 (2016-08-23)
===============================

-  Update release script
-  Config updates
-  Sort properly while formatting datetimes
-  Continue ALB support

Changes for v0.9.7 (2016-08-17)
===============================

-  Add babel and format relative dates
-  Add aegea elb create
-  Changes in support of app deploy infrastructure
-  Add R default mirror config
-  IAM principal lists now report attached policies

Changes for v0.9.6 (2016-08-14)
===============================

Continue release script

Changes for v0.9.5 (2016-08-14)
===============================

Continue release script

Version 0.7.0 (2016-05-29)
--------------------------
- Introduce rds subcommand

Version 0.6.0 (2016-05-29)
--------------------------
- Rollup: many changes

Version 0.5.0 (2016-05-05)
--------------------------
- Rollup: many changes

Version 0.4.0 (2016-04-19)
--------------------------
- aegea audit implementation (except section 4)
- numerous image improvements

Version 0.3.0 (2016-04-12)
--------------------------
- Rollup: many changes

Version 0.2.3 (2016-03-30)
--------------------------
- Rollup: many changes

Version 0.2.1 (2016-03-12)
--------------------------
- Begin tracking version history
- Expand test suite
