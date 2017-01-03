export AWS_DEFAULT_AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
export AWS_DEFAULT_REGION=${AWS_DEFAULT_AZ::-1}
aws configure set default.region $AWS_DEFAULT_REGION
