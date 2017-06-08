## AWS Account cleaner

This utility tool will delete all resources from your AWS account. Whitelisted resources are saved. This tool is designed for resetting a non-critical AWS account such as a training or demo account.

### Currently supported resources:

- Cloudformation stacks
- EC2 key pairs

### Usage

Create a config from the sample file and edit it:

    cp config.sample.yml config.yml

Run cleaner:

    ./clean.py config.yml
