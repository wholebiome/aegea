#!/bin/bash -eux

source site.environment
source aegea/missions/arvados/environment

if [[ $ARVADOS_DB_HOST == "unset" ]]; then
    launch_result=$(aegea rds create --engine postgres --engine-version 9.3.14 --db-name "$ARVADOS_DB_NAME" --username "$ARVADOS_DB_USERNAME" --password "$ARVADOS_DB_PASSWORD" --db-instance-class "$ARVADOS_DB_RDS_INSTANCE_CLASS" "arvados-$(date +%s)")
    export ARVADOS_DB_HOST=$(echo "$launch_result" | jq --raw-output .Endpoint.Address)
fi

# Restore protocol: install from scratch, restore RDS snapshot, dpkg reconfigure arvados-...-server (for migrations)

aegea-build-ami-for-mission arvados arvados-$(date "+%Y-%m-%d-%H-%M")
host=arvados-$(date "+%Y-%m-%d-%H-%M")
aegea launch $host --wait-for-ssh

export ARVADOS_ELB_INWARD_SG=aegea.launch
export ARVADOS_ELB_OUTWARD_SG=http+https
aegea elb create arvados-sso $host --dns-alias auth.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG --instance-port 2000
aegea elb create arvados-api $host --dns-alias $ARVADOS_UUID_PREFIX.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG --instance-port 2001
aegea elb create arvados-workbench $host --dns-alias workbench.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 2002
aegea elb create arvados-keepproxy $host --dns-alias keep.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 25107

# keep-web aliases:
#download.uuid_prefix.your.domain
#collections.uuid_prefix.your.domain
#*.collections.uuid_prefix.your.domain
#aegea elb create arvados-keepweb $host --dns-alias keep.$ARVADOS_UUID_PREFIX.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 

aegea zones update $DNS_ZONE "*.$ARVADOS_UUID_PREFIX.arvados" "$ARVADOS_UUID_PREFIX.arvados"

ARVADOS_SUPERUSER_TOKEN=$(aegea ssh ubuntu@$host "cd /var/www/arvados-api/current; sudo -u www-data RAILS_ENV=production bundle exec script/create_superuser_token.rb")
aegea ssh ubuntu@$host "export PGUSER=$ARVADOS_DB_USERNAME PGPASSWORD=$ARVADOS_DB_PASSWORD PGHOST=$ARVADOS_DB_HOST; createuser --no-superuser --no-createrole --createdb --encrypted --no-password arvados_sso; createdb arvados_production -T template0 -E UTF8 -O $ARVADOS_DB_USERNAME; psql -c \"ALTER USER arvados_sso WITH UNENCRYPTED PASSWORD '$ARVADOS_DB_PASSWORD'\""
aegea ssh ubuntu@$host "source /etc/profile; export ARVADOS_API_TOKEN=$ARVADOS_SUPERUSER_TOKEN; arv keep_service create --keep-service \"\$(cat /etc/keep.conf.json)\""

# /etc/arvados/crunch-dispatch-slurm/crunch-dispatch-slurm.yml - replace crunch dispatch token
# Custom SSL: PEM=/tmp/stunnel.pem; openssl genrsa > $PEM; openssl req -new -x509 -key $PEM -subj / >> $PEM; stunnel -d 443 -r 2001 -p $PEM; ARVADOS_API_HOST_INSECURE=1
# edit /var/www/arvados-sso/current/app/views/application/_links.html.erb to remove edit_user_registration

#Enter the following commands at the console. The values that appear after you assign app_id and app_secret correspond to the values for sso_app_id and sso_app_secret, respectively, in the API server’s SSO settings.

#:001 > c = Client.new
#:002 > c.name = "joshid"
#:003 > c.app_id = "arvados-server"
#:004 > c.app_secret = rand(2**400).to_s(36)
#=> "save this string for your API server's sso_app_secret"
#:005 > c.save!
