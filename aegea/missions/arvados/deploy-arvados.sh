#!/bin/bash -eux

source site.environment
source aegea/missions/arvados/environment

if [[ $ARVADOS_DB_HOST == "unset" ]]; then
    launch_result=$(aegea rds create --engine postgres --engine-version 9.3.14 --db-name "$ARVADOS_DB_NAME" --username "$ARVADOS_DB_USERNAME" --password "$ARVADOS_DB_PASSWORD" --db-instance-class "$ARVADOS_DB_RDS_INSTANCE_CLASS" "arvados-$(date +%s)")
    export ARVADOS_DB_HOST=$(echo "$launch_result" | jq --raw-output .Endpoint.Address)
fi

# Restore protocol: install from scratch, restore RDS snapshot, dpkg reconfigure arvados-...-server (for migrations)

export ARVADOS_INSTANCE=arvados-$(date "+%Y-%m-%d-%H-%M")
export ARVADOS_SLURMCTL_HOST=$ARVADOS_INSTANCE

aegea-build-image-for-mission --image-type ami arvados-worker arvwrkr-$(date "+%Y-%m-%d-%H-%M") --tags arvados-class=dynamic-compute cluster=$ARVADOS_UUID_PREFIX

aws iam create-user --user-name arvados || true
aws iam attach-user-policy --user-name arvados --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
for i in $(aws iam list-access-keys --user-name arvados | jq --raw-output .AccessKeyMetadata[].AccessKeyId); do
    aws iam delete-access-key --user-name arvados --access-key-id $i
done
create_access_key_output=$(aws iam create-access-key --user-name arvados)

export ARVADOS_AWS_DEFAULT_REGION=$(aws ec2 describe-availability-zones | jq --raw-output .AvailabilityZones[0].RegionName)
export ARVADOS_AWS_ACCESS_KEY_ID=$(echo "$create_access_key_output" | jq --raw-output .AccessKey.AccessKeyId)
export ARVADOS_AWS_SECRET_ACCESS_KEY=$(echo "$create_access_key_output" | jq --raw-output .AccessKey.SecretAccessKey)
# FIXME: ANM needs access to the private key for this
export ARVADOS_EC2_SSH_KEYPAIR_NAME=aegea.launch
export ARVADOS_EC2_WORKER_AMI_ID=$(aegea images --json --tag AegeaMission=arvados-worker | jq --raw-output .[].id | tail -n 1)
export ARVADOS_EC2_SUBNET_ID=$(aegea subnets --json | jq --raw-output .[].id | head -n 1)
export ARVADOS_EC2_SG_ID=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$ARVADOS_EC2_SG_NAME | jq --raw-output .SecurityGroups[].GroupId)

aegea-build-image-for-mission --image-type ami arvados arvados-$(date "+%Y-%m-%d-%H-%M")

aegea launch $ARVADOS_INSTANCE --instance-type m3.large --ami-tags AegeaMission=arvados --wait-for-ssh --commands "echo manual > /etc/init/arvados-keep.override"

for service in keep0 keep1; do
    aegea launch ${ARVADOS_INSTANCE}-$service --instance-type c4.xlarge --ami-tags AegeaMission=arvados --wait-for-ssh --commands "echo manual > /etc/init/arvados-api.override"
    aegea zones update $ARVADOS_PRIVATE_DNS_ZONE "arvados-$service=${ARVADOS_INSTANCE}-${service}.$ARVADOS_PRIVATE_DNS_ZONE"
    EBS_VOLUME=$(aegea ebs create --size-gb 40 --volume-type gp2 --tags Name=${ARVADOS_INSTANCE}-$service | jq --raw-output .VolumeId)
    aegea ebs attach $EBS_VOLUME ${ARVADOS_INSTANCE}-$service xvdz
    aegea ssh ubuntu@${ARVADOS_INSTANCE}-$service "sudo bash -ec 'mkdir -p /mnt/keep; mkfs.ext4 /dev/xvdz; mount /dev/xvdz /mnt/keep; service arvados-keep restart'"
done

aegea zones update $ARVADOS_PRIVATE_DNS_ZONE "arvados=$ARVADOS_INSTANCE.$ARVADOS_PRIVATE_DNS_ZONE"
aegea zones update $ARVADOS_PRIVATE_DNS_ZONE $(for i in {001..256}; do echo arv-worker-${i}=192.0.2.1; done)

export ARVADOS_ELB_INWARD_SG=aegea.launch
export ARVADOS_ELB_OUTWARD_SG=http+https
aegea elb create arvados-sso $ARVADOS_INSTANCE --dns-alias auth.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG --instance-port 2000
aegea elb create arvados-api $ARVADOS_INSTANCE --dns-alias $ARVADOS_UUID_PREFIX.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG --instance-port 2001
aegea elb create arvados-workbench $ARVADOS_INSTANCE --dns-alias workbench.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 2002
aegea elb create arvados-keepproxy $ARVADOS_INSTANCE --dns-alias keep.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 25107

# keep-web aliases:
#download.uuid_prefix.your.domain
#collections.uuid_prefix.your.domain
#*.collections.uuid_prefix.your.domain
#aegea elb create arvados-keepweb $ARVADOS_INSTANCE --dns-alias keep.$ARVADOS_UUID_PREFIX.$ARVADOS_HOSTNAME --security-groups $ARVADOS_ELB_INWARD_SG $ARVADOS_ELB_OUTWARD_SG  --instance-port 

aegea zones update $PUBLIC_DNS_ZONE "*.$ARVADOS_UUID_PREFIX.arvados=$ARVADOS_UUID_PREFIX.arvados.$PUBLIC_DNS_ZONE"

#ARVADOS_SUPERUSER_TOKEN=$(aegea ssh ubuntu@$ARVADOS_INSTANCE "cd /var/www/arvados-api/current; sudo -u www-data RAILS_ENV=production bundle exec script/create_superuser_token.rb")
aegea ssh ubuntu@$ARVADOS_INSTANCE "export PGUSER=$ARVADOS_DB_USERNAME PGPASSWORD=$ARVADOS_DB_PASSWORD PGHOST=$ARVADOS_DB_HOST; createuser --no-superuser --no-createrole --createdb --encrypted --no-password arvados_sso; createdb arvados_production -T template0 -E UTF8 -O $ARVADOS_DB_USERNAME; psql -c \"ALTER USER arvados_sso WITH UNENCRYPTED PASSWORD '$ARVADOS_DB_PASSWORD'\""
aegea ssh ubuntu@$ARVADOS_INSTANCE "sudo init-arvados"

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

#for i in $(arv keep_service list|jq .items[].uuid --raw-output); do arv keep_service destroy --uuid $i; done
