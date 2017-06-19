## AWS Account cleaner

This utility tool will delete all resources from your AWS account. Whitelisted resources are saved. This tool is designed for resetting a non-critical AWS account such as a training or demo account.

### Currently supported resources:

- CloudFormation stacks
- EC2 key pairs
- EC2 AMI images
- EC2 security groups
- EBS snapshots
- CloudWatch alarms
- SNS topics
- S3 buckets

### Usage

Create a config from the sample file and edit it:

    cp config.sample.yml config.yml

Run cleaner:

    ./clean.py config.yml

### Disclaimer

This tool is provided as-is, use at your own risk!
