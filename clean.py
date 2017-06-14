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
        self.cloudwatch = self.boto_session.client("cloudwatch")
        self.ec2 = self.boto_session.client("ec2")
        self.iam = self.boto_session.client("iam")
        self.s3 = self.boto_session.client("s3")
        self.s3_resource = self.boto_session.resource("s3")
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

    def _get_deletable_resources(self, describe_function, preserve_key, list_key, item_key):
        resource_list = describe_function().get(list_key, [])
        resources = {}
        for resource in resource_list:
            if resource[item_key] not in self.config.get("preserved_resources", {}).get(preserve_key, []):
                resources[resource[item_key]] = resource
        return resources

    def _delete_generic_resource(self, resources, human_name, delete_function, delete_key):
        if resources:
            print("{} that will be deleted:\n".format(human_name), yaml.safe_dump(resources, default_flow_style=False))
            if self._ask("Delete {}?".format(human_name), "no"):
                for key, resource in resources.iteritems():
                    print("Deleting", key)
                    kwargs = {delete_key: key}
                    delete_function(**kwargs)
        else:
            print("No {} to delete".format(human_name))

    def _simple_delete(self, describe_function, delete_function, preserve_key, list_key, item_key):
        deletables = self._get_deletable_resources(describe_function, preserve_key, list_key, item_key)
        self._delete_generic_resource(deletables, list_key, delete_function, item_key)

    def show_config(self):
        print("Current configuration:\n", yaml.dump(self.config, default_flow_style=False))

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
        if stacks_to_delete:
            print("Stacks that will be deleted:", stacks_to_delete)
            if self._ask("Delete stacks?", "no"):
                for stack in stacks_to_delete: self.cf.delete_stack(StackName=stack)
        else:
            print("No stacks to delete")

    def delete_key_pairs(self):
        self._simple_delete(self.ec2.describe_key_pairs, self.ec2.delete_key_pair, "ec2_key_pairs", "KeyPairs", "KeyName")

    def delete_amis(self):
        images = self.ec2.describe_images(
            Owners=[self.sts.get_caller_identity().get("Account")]
        )
        images_to_delete = [image.get("ImageId") 
            for image in images.get("Images")
            if image.get("ImageId") 
            not in self.config.get("preserved_resources", {}).get("ami", [])]
        if images_to_delete:
            print("AMIs that will be deleted:", images_to_delete)
            if self._ask("Delete images?", "no"):
                for image in images_to_delete: self.ec2.deregister_image(ImageId=image)
        else:
            print("No images to delete")

    def delete_snapshots(self):
        snapshots = self.ec2.describe_snapshots(
            OwnerIds=[self.sts.get_caller_identity().get("Account")]
        )
        snapshots_to_delete = [snapshot.get("SnapshotId") 
            for snapshot in snapshots.get("Snapshots")
            if snapshot.get("SnapshotId") 
            not in self.config.get("preserved_resources", {}).get("snapshots", [])]
        if snapshots_to_delete:
            print("Snapshots that will be deleted:", snapshots_to_delete)
            if self._ask("Delete snapshots?", "no"):
                for snapshot in snapshots_to_delete: self.ec2.delete_snapshot(SnapshotId=snapshot)
        else:
            print("No snapshots to delete")

    def delete_cloudwatch_alarms(self):
        alarms = self.cloudwatch.describe_alarms()
        alarms_to_delete = [alarm.get("AlarmName") 
            for alarm in alarms.get("MetricAlarms")
            if alarm.get("AlarmName") 
            not in self.config.get("preserved_resources", {}).get("cloudwatch_alarms", [])]
        if alarms_to_delete:
            print("Alarms that will be deleted:", alarms_to_delete)
            if self._ask("Delete alarms?", "no"):
                self.cloudwatch.delete_alarms(AlarmNames=alarms_to_delete)
        else:
            print("No alarms to delete")

    def delete_buckets(self):
        buckets = self.s3.list_buckets()
        buckets_to_delete = [bucket.get("Name") 
            for bucket in buckets.get("Buckets")
            if bucket.get("Name") 
            not in self.config.get("preserved_resources", {}).get("s3_buckets", [])]
        if buckets_to_delete:
            print("Buckets that will be deleted:", buckets_to_delete)
            if self._ask("Delete buckets?", "no"):
                for bucket_name in buckets_to_delete:
                    bucket = self.s3_resource.Bucket(bucket_name)
                    bucket.object_versions.delete()
                    bucket.delete()
        else:
            print("No buckets to delete")

    def delete_securitygroups(self):
        securitygroups = self.ec2.describe_security_groups()
        securitygroups_to_delete = [group.get("GroupId") 
            for group in securitygroups.get("SecurityGroups")
            if group.get("GroupId") 
            not in self.config.get("preserved_resources", {}).get("securitygroups", [])
            and group.get("GroupName") != "default"
            ]
        if securitygroups_to_delete:
            print("Security groups that will be deleted:", securitygroups_to_delete)
            if self._ask("Delete security groups?", "no"):
                for group in securitygroups_to_delete: self.ec2.delete_security_group(GroupId=group)
        else:
            print("No alarms to delete")


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
    cleaner.delete_cloudwatch_alarms()
    cleaner.delete_amis()
    cleaner.delete_snapshots()
    cleaner.delete_securitygroups()
    cleaner.delete_key_pairs()
    cleaner.delete_buckets()
