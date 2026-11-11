"""cfn-update-stack-add-s3-export-role-positive."""
from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-stack-add-s3-export-role-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "S2r" + secrets.token_urlsafe(18)


def _role_resource(bucket_logical_id: str) -> dict[str, Any]:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
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
                    "PolicyName": "s3-access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:ListBucket",
                                    "s3:PutObject",
                                ],
                                "Resource": [
                                    {"Fn::GetAtt": [bucket_logical_id, "Arn"]},
                                    {
                                        "Fn::Join": [
                                            "",
                                            [{"Fn::GetAtt": [bucket_logical_id, "Arn"]}, "/*"],
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


def _base_template(db_id: str, *, subnet_group: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"MasterPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket"},
            "S3ImportRole": _role_resource("DataBucket"),
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
                        {"FeatureName": "s3Import", "RoleArn": {"Fn::GetAtt": ["S3ImportRole", "Arn"]}}
                    ],
                    "DBSubnetGroupName": subnet_group,
                },
                "DependsOn": ["S3ImportRole"],
            },
        },
        "Outputs": {
            "ImportRoleArn": {"Value": {"Fn::GetAtt": ["S3ImportRole", "Arn"]}},
        },
    }


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating a deployed stack to ADD a second (s3Export) IAM role association -- while the
    original s3Import association stays in place -- is reflected in DescribeDBInstances only
    after the update completes, with both roles present and correctly featured."""
    db_id = _xname(ctx, "db")
    rds = ctx.client("rds")
    # One subnet group for both template versions: a changed DBSubnetGroupName would make the
    # update replace the named instance, which CloudFormation cannot do (update rollback).
    subnet_group = _network_db_subnet_group(ctx, rds)

    initial = _deploy_cfn(
        ctx,
        json.dumps(_base_template(db_id, subnet_group=subnet_group)),
        parameters={"MasterPassword": _DB_PASSWORD},
        timeout_s=1200.0,
    )
    stack_name = initial["stack_name"]
    import_role_arn = initial["outputs"]["ImportRoleArn"]

    def _roles_by_feature():
        desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        return {r["FeatureName"]: r for r in desc.get("AssociatedRoles", [])}

    before = _poll_until(
        _roles_by_feature,
        lambda rs: rs.get("s3Import", {}).get("Status") in ("ACTIVE", "INVALID"),
        timeout_s=300.0,
        interval_s=10.0,
        description="initial s3Import association to settle",
    )
    assert before.get("s3Import", {}).get("Status") == "ACTIVE", (
        f"expected initial s3Import association ACTIVE, got {before.get('s3Import')!r}"
    )
    # Before the update, no s3Export association exists at all.
    assert "s3Export" not in before, (
        f"expected no s3Export association before the update, got {before.get('s3Export')!r}"
    )

    updated_template = _base_template(db_id, subnet_group=subnet_group)
    updated_template["Resources"]["S3ExportRole"] = _role_resource("DataBucket")
    updated_template["Resources"]["DBInstance"]["Properties"]["AssociatedRoles"].append(
        {"FeatureName": "s3Export", "RoleArn": {"Fn::GetAtt": ["S3ExportRole", "Arn"]}}
    )
    updated_template["Resources"]["DBInstance"]["DependsOn"] = ["S3ImportRole", "S3ExportRole"]
    updated_template["Outputs"]["ExportRoleArn"] = {"Value": {"Fn::GetAtt": ["S3ExportRole", "Arn"]}}

    update_outputs = _update_stack_and_wait(ctx, stack_name, json.dumps(updated_template))
    export_role_arn = update_outputs["ExportRoleArn"]

    after = _poll_until(
        _roles_by_feature,
        lambda rs: rs.get("s3Export", {}).get("Status") in ("ACTIVE", "INVALID"),
        timeout_s=300.0,
        interval_s=10.0,
        description="post-update s3Export association to settle",
    )
    assert set(after.keys()) == {"s3Import", "s3Export"}, (
        f"expected exactly {{'s3Import', 's3Export'}} associated after the update, got {set(after.keys())!r}"
    )
    assert after["s3Import"]["RoleArn"] == import_role_arn, (
        f"expected s3Import RoleArn to stay {import_role_arn!r}, got {after['s3Import']['RoleArn']!r}"
    )
    assert after["s3Import"]["Status"] == "ACTIVE", (
        f"expected s3Import to remain ACTIVE after the update, got {after['s3Import']['Status']!r}"
    )
    assert after["s3Export"]["RoleArn"] == export_role_arn, (
        f"expected new s3Export RoleArn {export_role_arn!r}, got {after['s3Export']['RoleArn']!r}"
    )
    assert after["s3Export"]["Status"] == "ACTIVE", (
        f"expected new s3Export association ACTIVE, got {after['s3Export']['Status']!r}"
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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
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


def _update_stack_and_wait(ctx, stack_name: str, template_body: str, *, timeout_s: float = 900.0) -> dict[str, str]:
    """update_stack + poll to a terminal status; returns the post-update Outputs map.

    Not part of the canonical create-only helper set above -- CFN update semantics (as opposed
    to create) are specific to this check's deployment-order scenario.
    """
    cfn = ctx.client("cloudformation")
    current_params = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Parameters", [])
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": p["ParameterKey"], "UsePreviousValue": True} for p in current_params
        ],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith("_COMPLETE") or s.endswith("_FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"update stack {stack_name}",
    )
    if final_status != "UPDATE_COMPLETE":
        raise AssertionError(f"stack update ended in {final_status}")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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
