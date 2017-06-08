#!/usr/bin/env python

from __future__ import print_function
import sys
import boto3
import yaml

class Cleaner:

    def __init__(self, config):
        self.config = config
        self.boto_session = boto3.Session(profile_name=self.config.get("profile_name"))

    def show_config(self):
        print(yaml.dump(self.config))

    def run_safety_checks(self):
        # AWS Account ID in config.yml must match the account we are accessing using an API key
        account_id = self.boto_session.client("sts").get_caller_identity().get("Account")
        assert account_id == self.config.get("assertions").get("account_id"), "Unexpected AWS Account ID, check configuration!"

        # IAM username in config.yml must match the IAM user whose API key we are using
        iam = self.boto_session.resource("iam")
        current_user = iam.CurrentUser().user_name
        assert current_user == self.config.get("assertions").get("iam_username"), "Unexpected IAM User name, check configuration!"

        print("You are {} on account {}".format(current_user, account_id))

    def delete_cloudformation_stacks(self):
        cf = self.boto_session.client("cloudformation")
        stacks = cf.list_stacks(StackStatusFilter=[
            "CREATE_FAILED",
            "CREATE_COMPLETE",
            "ROLLBACK_FAILED",
            "ROLLBACK_COMPLETE",
            "DELETE_FAILED",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE"
        ])
        stacks_to_delete = [stack.get("StackName") 
            for stack in stacks.get("StackSummaries") 
            if stack.get("StackName") 
            not in self.config.get("preserved_resources").get("cloudformation")]
        print("Deleting stacks", stacks_to_delete)
        for stack in stacks_to_delete: cf.delete_stack(StackName=stack)

    def delete_key_pairs(self):
        ec2 = self.boto_session.client("ec2")
        keys = ec2.describe_key_pairs()
        keys_to_delete = [key.get("KeyName") 
            for key in keys.get("KeyPairs")
            if key.get("KeyName") 
            not in self.config.get("preserved_resources").get("ec2_key_pairs")]
        print("Deleting keys", keys_to_delete)
        for key in keys_to_delete: ec2.delete_key_pair(KeyName=key)

def _get_config_from_file(filename):
    config = {}
    with open(filename, "r") as stream:
        config = yaml.load(stream)
    return config


if __name__ == "__main__":
    cleaner = Cleaner(_get_config_from_file(sys.argv[1]))
    cleaner.show_config()
    cleaner.run_safety_checks()
    cleaner.delete_cloudformation_stacks()
    cleaner.delete_key_pairs()
