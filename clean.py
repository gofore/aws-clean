#!/usr/bin/env python

from __future__ import print_function
import sys
import boto3
import yaml

class Cleaner:

    def __init__(self, config):
        self.config = config
        self.boto_session = boto3.Session(profile_name=self.config.get("profile_name"))
        self.cf = self.boto_session.client("cloudformation")
        self.ec2 = self.boto_session.client("ec2")
        self.iam = self.boto_session.client("iam")
        self.sts = self.boto_session.client("sts")

    def _ask(self, question, default="no"):
        valid = {"yes": True, "y": True, "no": False, "n": False}
        if default is None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("Invalid default answer: '%s'" % default)
        while True:
            sys.stdout.write(question + prompt)
            choice = raw_input().lower()
            if default is not None and choice == "":
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please answer 'yes' or 'no' (or 'y' or 'n').\n")

    def show_config(self):
        print(yaml.dump(self.config))

    def run_safety_checks(self):
        # AWS Account ID in config.yml must match the account we are accessing using an API key
        account_id = self.sts.get_caller_identity().get("Account")
        assert account_id == self.config.get("assertions").get("account_id"), "Unexpected AWS Account ID, check configuration!"

        # AWS Account alias in config.yml must match the account alias
        account_aliases = self.iam.list_account_aliases().get("AccountAliases")
        assert len(account_aliases) == 1, "AWS Account should have exactly one alias"
        account_alias = account_aliases[0]
        assert account_alias == self.config.get("assertions").get("account_alias"), "Unexpected AWS Account alias, check configuration!"

        # IAM username in config.yml must match the IAM user whose API key we are using
        iam_resource = self.boto_session.resource("iam")
        current_user = iam_resource.CurrentUser().user_name
        assert current_user == self.config.get("assertions").get("iam_username"), "Unexpected IAM User name, check configuration!"

        print("You are {} on account {} ({})".format(current_user, account_id, account_alias))
        if not self._ask("Proceed?", "no"): sys.exit()

    def delete_cloudformation_stacks(self):
        stacks = self.cf.list_stacks(StackStatusFilter=[
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
        print("Stacks that will be deleted:", stacks_to_delete)
        if not self._ask("Delete?", "no"): sys.exit()
        for stack in stacks_to_delete: self.cf.delete_stack(StackName=stack)

    def delete_key_pairs(self):
        keys = self.ec2.describe_key_pairs()
        keys_to_delete = [key.get("KeyName") 
            for key in keys.get("KeyPairs")
            if key.get("KeyName") 
            not in self.config.get("preserved_resources").get("ec2_key_pairs")]
        print("Keys that will be deleted:", keys_to_delete)
        if not self._ask("Delete?", "no"): sys.exit()
        for key in keys_to_delete: self.ec2.delete_key_pair(KeyName=key)


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
