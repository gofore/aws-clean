#!/usr/bin/env python

from __future__ import print_function
import sys
import yaml

class Cleaner:

    def __init__(self, config):
        self.config = config

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

    def _get_deletable_resources(self, describe_function, describe_args, preserve_key, list_key, item_key, filter_function=None):
        resources = describe_function(**describe_args).get(list_key, [])
        preserved_resources = self.config.get("preserved_resources", {}).get(preserve_key, [])
        def can_be_deleted(key, preserved_resources, resource):
            if filter_function:
                return filter_function(resource) and key not in preserved_resources
            else:
                return key not in preserved_resources
        return {resource[item_key]: resource for resource in resources if can_be_deleted(resource[item_key], preserved_resources, resource)}

    def _delete_generic_resource(self, resources, human_name, delete_function, delete_key):
        if resources:
            print("{} that will be deleted:\n".format(human_name) + yaml.safe_dump(resources, default_flow_style=False))
            if self._ask("Delete {}?".format(human_name), "no"):
                for key, resource in resources.iteritems():
                    print("Deleting", key)
                    kwargs = {delete_key: key}
                    delete_function(**kwargs)
        else:
            print("No {} to delete".format(human_name))

    def _simple_delete(self, describe_function, delete_function, preserve_key, list_key, item_key, describe_args={}, filter_function=None):
        deletables = self._get_deletable_resources(describe_function, describe_args, preserve_key, list_key, item_key, filter_function)
        self._delete_generic_resource(deletables, list_key, delete_function, item_key)

    def run_safety_checks(self, sts, iam, iam_resource):
        # AWS Account ID in config.yml must match the account we are accessing using an API key
        account_id = sts.get_caller_identity().get("Account")
        assert account_id == self.config.get("assertions").get("account_id"), "Unexpected AWS Account ID, check configuration!"

        # AWS Account alias in config.yml must match the account alias
        account_aliases = iam.list_account_aliases().get("AccountAliases")
        assert len(account_aliases) == 1, "AWS Account should have exactly one alias"
        account_alias = account_aliases[0]
        assert account_alias == self.config.get("assertions").get("account_alias"), "Unexpected AWS Account alias, check configuration!"

        # IAM username in config.yml must match the IAM user whose API key we are using
        current_user = iam_resource.CurrentUser().user_name
        assert current_user == self.config.get("assertions").get("iam_username"), "Unexpected IAM User name, check configuration!"

        print("You are {} on account {} ({})".format(current_user, account_id, account_alias))
        if not self._ask("Proceed?", "no"): sys.exit()

    def delete_cloudformation_stacks(self, cf):
        args = {
            "StackStatusFilter": [
                "CREATE_FAILED",
                "CREATE_COMPLETE",
                "ROLLBACK_FAILED",
                "ROLLBACK_COMPLETE",
                "DELETE_FAILED",
                "UPDATE_COMPLETE",
                "UPDATE_ROLLBACK_FAILED",
                "UPDATE_ROLLBACK_COMPLETE"
            ]
        }
        self._simple_delete(cf.list_stacks, cf.delete_stack, "cloudformation", "StackSummaries", "StackName", args)

    def delete_key_pairs(self, ec2):
        self._simple_delete(ec2.describe_key_pairs, ec2.delete_key_pair, "ec2_key_pairs", "KeyPairs", "KeyName")

    def delete_amis(self, sts, ec2):
        args = {
            "Owners": [sts.get_caller_identity().get("Account")]
        }
        self._simple_delete(ec2.describe_images, ec2.deregister_image, "ami", "Images", "ImageId", args)

    def delete_snapshots(self, sts, ec2):
        args = {
            "OwnerIds": [sts.get_caller_identity().get("Account")]
        }
        self._simple_delete(ec2.describe_snapshots, ec2.delete_snapshot, "snapshots", "Snapshots", "SnapshotId", args)

    def delete_cloudwatch_alarms(self, cloudwatch):
        alarms = cloudwatch.describe_alarms()
        alarms_to_delete = [alarm.get("AlarmName") 
            for alarm in alarms.get("MetricAlarms")
            if alarm.get("AlarmName") 
            not in self.config.get("preserved_resources", {}).get("cloudwatch_alarms", [])]
        if alarms_to_delete:
            print("Alarms that will be deleted:", alarms_to_delete)
            if self._ask("Delete alarms?", "no"):
                cloudwatch.delete_alarms(AlarmNames=alarms_to_delete)
        else:
            print("No alarms to delete")

    def delete_buckets(self, s3, s3_resource):
        def delete_bucket_and_its_objects(Name):
            bucket = s3_resource.Bucket(Name)
            bucket.object_versions.delete()
            bucket.delete()
        self._simple_delete(s3.list_buckets, delete_bucket_and_its_objects, "s3_buckets", "Buckets", "Name")

    def delete_securitygroups(self, ec2):
        def not_default(resource):
            return resource["GroupName"] != "default"
        self._simple_delete(
            ec2.describe_security_groups, 
            ec2.delete_security_group, 
            "securitygroups", 
            "SecurityGroups", 
            "GroupId", 
            filter_function=not_default
        )

    def delete_sns_topics(self, sns):
        self._simple_delete(sns.list_topics, sns.delete_topic, "sns_topics", "Topics", "TopicArn")


def _get_config_from_file(filename):
    config = {}
    with open(filename, "r") as stream:
        config = yaml.load(stream)
    return config

def get_boto_session(profile_name):
    import boto3
    return boto3.Session(profile_name=profile_name)

if __name__ == "__main__":
    config = _get_config_from_file(sys.argv[1])
    cleaner = Cleaner(config)
    print("Current configuration:\n", yaml.dump(config, default_flow_style=False))

    boto_session = get_boto_session(config["profile_name"])

    cf = boto_session.client("cloudformation")
    cloudwatch = boto_session.client("cloudwatch")
    ec2 = boto_session.client("ec2")
    iam = boto_session.client("iam")
    iam_resource = boto_session.resource("iam")
    s3 = boto_session.client("s3")
    s3_resource = boto_session.resource("s3")
    sts = boto_session.client("sts")
    sns = boto_session.client("sns")

    cleaner.run_safety_checks(sts, iam, iam_resource)
    cleaner.delete_cloudformation_stacks(cf)
    cleaner.delete_cloudwatch_alarms(cloudwatch)
    cleaner.delete_sns_topics(sns)
    cleaner.delete_amis(sts, ec2)
    cleaner.delete_snapshots(sts, ec2)
    cleaner.delete_securitygroups(ec2)
    cleaner.delete_key_pairs(ec2)
    cleaner.delete_buckets(s3, s3_resource)
