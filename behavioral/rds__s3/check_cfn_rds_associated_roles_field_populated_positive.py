"""cfn-rds-associated-roles-field-populated-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-associated-roles-field-populated-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real9!Behave"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed DBInstance's AssociatedRoles.RoleArn is byte-for-byte the ARN
    iam:GetRole returns for the target role in the same stack, not a decoy role's ARN or a
    normalized variant of it."""
    db_id = _xname(ctx, "db")
    target_role_name = _xname(ctx, "target-role")
    decoy_role_name = _xname(ctx, "decoy-role")

    def _trusted_role(role_name: str) -> dict[str, Any]:
        return {
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
                        "PolicyName": "s3-import-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": [
                                        {"Fn::GetAtt": ["ImportBucket", "Arn"]},
                                        {
                                            "Fn::Join": [
                                                "",
                                                [{"Fn::GetAtt": ["ImportBucket", "Arn"]}, "/*"],
                                            ]
                                        },
                                    ],
                                }
                            ],
                        },
                    }
                ],
            },
        }

    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"MasterPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "ImportBucket": {"Type": "AWS::S3::Bucket"},
            # Two equally-valid, equally-trusted roles exist in the stack. Only TargetRole is
            # referenced by AssociatedRoles -- a faithful emulator must resolve to exactly that
            # one, not to whichever role it created/processed most recently.
            "TargetRole": _trusted_role(target_role_name),
            "DecoyRole": _trusted_role(decoy_role_name),
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": db_id,
                    "Engine": "postgres",
                    "DBInstanceClass": "db.t3.micro",
                    "AllocatedStorage": "20",
                    "MasterUsername": "dbadmin",
                    "MasterUserPassword": {"Ref": "MasterPassword"},
                    "BackupRetentionPeriod": 0,
                    "PubliclyAccessible": False,
                    "MultiAZ": False,
                    "DeletionProtection": False,
                    "AssociatedRoles": [
                        {"FeatureName": "s3Import", "RoleArn": {"Fn::GetAtt": ["TargetRole", "Arn"]}}
                    ],
                    "DBSubnetGroupName": subnet_group,
                },
                "DependsOn": ["TargetRole", "DecoyRole"],
            },
        },
        "Outputs": {
            "TargetRoleArn": {"Value": {"Fn::GetAtt": ["TargetRole", "Arn"]}},
            "DecoyRoleArn": {"Value": {"Fn::GetAtt": ["DecoyRole", "Arn"]}},
        },
    }

    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"MasterPassword": _DB_PASSWORD},
        timeout_s=1200.0,
    )
    target_arn_from_stack = result["outputs"]["TargetRoleArn"]
    decoy_arn_from_stack = result["outputs"]["DecoyRoleArn"]

    iam = ctx.client("iam")
    target_arn_from_iam = iam.get_role(RoleName=target_role_name)["Role"]["Arn"]
    assert target_arn_from_iam == target_arn_from_stack, (
        f"IAM's own record of {target_role_name} ({target_arn_from_iam!r}) does not match the "
        f"ARN CFN reported for it ({target_arn_from_stack!r})"
    )

    rds = ctx.client("rds")

    def _probe():
        desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        return desc.get("AssociatedRoles", [])

    roles = _poll_until(
        _probe,
        lambda rs: len(rs) >= 1 and rs[0].get("Status") in ("ACTIVE", "INVALID"),
        timeout_s=300.0,
        interval_s=10.0,
        description=f"AssociatedRoles on {db_id} to settle",
    )
    assert len(roles) == 1, f"expected exactly one associated role, got {roles!r}"
    entry = roles[0]
    assert entry["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import', got {entry['FeatureName']!r}"
    )
    # The precise-ARN-resolution assertion: it must be the target role's ARN exactly, resolved
    # independently via IAM, and NOT the decoy's ARN.
    assert entry["RoleArn"] == target_arn_from_iam, (
        f"AssociatedRoles.RoleArn {entry['RoleArn']!r} does not match the target role's IAM-"
        f"confirmed ARN {target_arn_from_iam!r}"
    )
    assert entry["RoleArn"] != decoy_arn_from_stack, (
        f"AssociatedRoles.RoleArn {entry['RoleArn']!r} resolved to the decoy role "
        f"{decoy_arn_from_stack!r} instead of the target role"
    )
    assert entry["Status"] == "ACTIVE", f"expected ACTIVE, got {entry['Status']!r}"

    # Delete the stack and prove the instance is gone with an independent read.
    _delete_stack_and_wait(ctx, result["stack_name"])
    try:
        rds.describe_db_instances(DBInstanceIdentifier=db_id)
        raise AssertionError(f"expected {db_id} to be gone after stack deletion, but it still describes")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "DBInstanceNotFound", (
            f"expected DBInstanceNotFound for {db_id} after stack deletion, got {code!r}"
        )
        message = e.response["Error"].get("Message", "")
        assert message == f"DBInstance {db_id} not found.", f"unexpected DBInstanceNotFound message: {message!r}"


# ===== helpers =====
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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=900,
        interval_s=10.0,
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
