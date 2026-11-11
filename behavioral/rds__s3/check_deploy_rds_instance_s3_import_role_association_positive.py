"""deploy-rds-instance-s3-import-role-association-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-instance-s3-import-role-association-positive"
GROUP = "iac-s3-import-role"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A DBInstance deployed with AssociatedRoles referencing an IAM role that trusts
    rds.amazonaws.com settles into an ACTIVE s3Import role association after deploy."""
    bucket_name = _xname(ctx, "s3import-bkt")
    role_name = _xname(ctx, "s3import-role")
    db_id = _xname(ctx, "s3import-db")
    master_password = _db_password(ctx)

    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    template = json.dumps(
        {
            "Resources": {
                "ImportBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket_name},
                },
                "ImportRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "rds.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "s3import-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetObject", "s3:ListBucket"],
                                            "Resource": [
                                                f"arn:aws:s3:::{bucket_name}",
                                                f"arn:aws:s3:::{bucket_name}/*",
                                            ],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "DBInstance": {
                    "Type": "AWS::RDS::DBInstance",
                    "DeletionPolicy": "Delete",
                    "DependsOn": "ImportRole",
                    "Properties": {
                        "DBInstanceIdentifier": db_id,
                        "Engine": "postgres",
                        "DBInstanceClass": "db.t3.micro",
                        "AllocatedStorage": "20",
                        "MasterUsername": "dbadmin",
                        "MasterUserPassword": master_password,
                        "PubliclyAccessible": False,
                        "BackupRetentionPeriod": 0,
                        "AssociatedRoles": [
                            {
                                "FeatureName": "s3Import",
                                "RoleArn": {"Fn::GetAtt": ["ImportRole", "Arn"]},
                            }
                        ],
                        "DBSubnetGroupName": subnet_group,
                    },
                },
            },
            "Outputs": {
                "RoleArn": {"Value": {"Fn::GetAtt": ["ImportRole", "Arn"]}},
            },
        }
    )

    deployed = _deploy_cfn(ctx, template, timeout_s=1800.0)
    role_arn = deployed["outputs"]["RoleArn"]

    rds = ctx.client("rds")

    def _associated_role():
        inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        for role in inst.get("AssociatedRoles", []):
            if role["FeatureName"] == "s3Import":
                return role
        return None

    def _role_status():
        role = _associated_role()
        return role["Status"] if role else None

    status = _poll_until(
        _role_status,
        lambda s: s in {"ACTIVE", "INVALID"},
        timeout_s=600.0,
        interval_s=15.0,
        description=f"s3Import AssociatedRole status settles for {db_id}",
    )
    assert status == "ACTIVE", f"expected ACTIVE s3Import role association, got {status!r}"

    role = _associated_role()
    assert role is not None, f"s3Import AssociatedRoles entry vanished for {db_id}"
    assert role["FeatureName"] == "s3Import", f"expected FeatureName s3Import, got {role['FeatureName']!r}"
    assert role["RoleArn"] == role_arn, (
        f"expected AssociatedRoles entry to reference the deployed ImportRole "
        f"{role_arn!r}, got {role['RoleArn']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _db_password(ctx: Any) -> str:
    suffix = ctx.unique_name("pw").rsplit("-", 1)[-1]
    return f"Sim2Real1{suffix}Aa"


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
