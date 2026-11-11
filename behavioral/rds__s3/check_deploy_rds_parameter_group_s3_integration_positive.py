"""deploy-rds-parameter-group-s3-integration-positive."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-parameter-group-s3-integration-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployed DB option group enabling SQLSERVER_BACKUP_RESTORE (S3 integration) resolves
    the IAM_ROLE_ARN option setting to the exact ARN of the deployed role, and the instance
    reports the option group membership as in-sync, end to end through the stack."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    engine_versions = rds.describe_db_engine_versions(Engine="sqlserver-ex", DefaultOnly=True)["DBEngineVersions"]
    if not engine_versions:
        raise AssertionError("no default sqlserver-ex engine version available in this region")
    full_version = engine_versions[0]["EngineVersion"]
    major_version = ".".join(full_version.split(".")[:2])

    db_id = _xname(ctx, "dbi")
    og_name = _xname(ctx, "og")
    template = _build_option_group_stack_template(major_version, og_name, db_id, ctx=ctx)
    password = secrets.token_urlsafe(12)
    stack = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"MasterUsername": "dbadmin", "MasterUserPassword": password},
        timeout_s=1200,
    )
    outputs = stack["outputs"]
    role_arn = outputs["S3IntegrationRoleArn"]
    role_name = role_arn.split("/")[-1]
    bucket_arn = outputs["BucketArn"]

    instance = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0],
        lambda i: i.get("OptionGroupMemberships", [{}])[0].get("Status") == "in-sync",
        timeout_s=600,
        interval_s=10.0,
        description=f"DB instance {db_id} option group membership in-sync",
    )
    assert instance["OptionGroupMemberships"][0]["OptionGroupName"] == og_name, (
        f"DB instance {db_id} reports option group membership "
        f"{instance['OptionGroupMemberships'][0]['OptionGroupName']!r}, expected {og_name!r}"
    )

    option_group = rds.describe_option_groups(OptionGroupName=og_name)["OptionGroupsList"][0]
    backup_restore = next(
        o for o in option_group["Options"] if o["OptionName"] == "SQLSERVER_BACKUP_RESTORE"
    )
    iam_setting = next(s for s in backup_restore["OptionSettings"] if s["Name"] == "IAM_ROLE_ARN")
    assert iam_setting["Value"] == role_arn, (
        f"option group's IAM_ROLE_ARN setting is {iam_setting['Value']!r}, expected the "
        f"deployed role ARN {role_arn!r}"
    )

    policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName="S3BackupRestoreAccess")["PolicyDocument"]
    resources = policy_doc["Statement"][0]["Resource"]
    assert bucket_arn in resources, (
        f"role's attached policy resources {resources!r} do not reference the deployed bucket "
        f"ARN {bucket_arn!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str, timeout_s: float = 700.0) -> None:
    """Delete the stack and wait until it is gone. A first delete that ends DELETE_FAILED (a
    resource still held by one that is deleting) is retried once; then the failed resources and
    their reasons are raised."""
    cfn = ctx.client("cloudformation")

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if "does not exist" in e.response["Error"].get("Message", ""):
                return "GONE"
            raise

    status = None
    for _ in range(2):
        cfn.delete_stack(StackName=stack_name)
        status = _poll_until(
            _status,
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=timeout_s,
            interval_s=15.0,
            description=f"delete stack {stack_name}",
        )
        if status != "DELETE_FAILED":
            return
    reasons = [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}"
        for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        if e["ResourceStatus"] == "DELETE_FAILED"
    ][:5]
    raise AssertionError(f"stack {stack_name} ended {status}: {reasons}")


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _build_option_group_stack_template(major_version: str, og_name: str, db_id: str, *, ctx) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterUserPassword": {"Type": "String", "NoEcho": True, "MinLength": 8},
        },
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Delete"},
            "S3IntegrationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "S3BackupRestoreAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:ListBucket",
                                            "s3:PutObject",
                                            "s3:GetObject",
                                            "s3:ListMultipartUploadParts",
                                            "s3:AbortMultipartUpload",
                                        ],
                                        "Resource": [
                                            {"Fn::GetAtt": ["Bucket", "Arn"]},
                                            {"Fn::Sub": "${Bucket.Arn}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "OptionGroup": {
                "Type": "AWS::RDS::OptionGroup",
                "Properties": {
                    "OptionGroupName": og_name,
                    "EngineName": "sqlserver-ex",
                    "MajorEngineVersion": major_version,
                    "OptionGroupDescription": "sim2real S3 integration option group",
                    "OptionConfigurations": [
                        {
                            "OptionName": "SQLSERVER_BACKUP_RESTORE",
                            "OptionSettings": [
                                {"Name": "IAM_ROLE_ARN", "Value": {"Fn::GetAtt": ["S3IntegrationRole", "Arn"]}}
                            ],
                        }
                    ],
                },
            },
            "DbInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": db_id,
                    "Engine": "sqlserver-ex",
                    "EngineVersion": major_version,
                    "LicenseModel": "license-included",
                    "DBInstanceClass": "db.t3.small",
                    "AllocatedStorage": "20",
                    "MasterUsername": {"Ref": "MasterUsername"},
                    "MasterUserPassword": {"Ref": "MasterUserPassword"},
                    "OptionGroupName": {"Ref": "OptionGroup"},
                    # No automated backups: a retained automated backup keeps the option group in
                    # use after the instance is gone, so the stack delete would fail on it.
                    "BackupRetentionPeriod": "0",
                    "PubliclyAccessible": False,
                    "DBSubnetGroupName": _network_db_subnet_group(ctx, ctx.client("rds")),
                },
            },
        },
        "Outputs": {
            "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
            "S3IntegrationRoleArn": {"Value": {"Fn::GetAtt": ["S3IntegrationRole", "Arn"]}},
        },
    }


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
