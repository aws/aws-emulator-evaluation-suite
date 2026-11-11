"""cfn-deploy-rds-s3-role-missing-trust-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-s3-role-missing-trust-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real9!Behave"


def _role_resource(principal: str, bucket_logical_id: str) -> dict[str, Any]:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
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


def _db_instance(db_id: str, role_logical_id: str) -> dict[str, Any]:
    return {
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
                {"FeatureName": "s3Import", "RoleArn": {"Fn::GetAtt": [role_logical_id, "Arn"]}}
            ],
        },
        "DependsOn": [role_logical_id],
    }


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose DBInstance AssociatedRoles names a role that does not trust rds.amazonaws.com
    fails as a whole (DBInstance CREATE_FAILED, stack rolled back), while the same stack with a
    trusting role reaches CREATE_COMPLETE with the association ACTIVE.
    """
    bad_db_id = _xname(ctx, "db-bad")

    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"MasterPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket"},
            # WRONG trust principal: ec2.amazonaws.com can never satisfy RDS's sts:AssumeRole.
            "BadTrustRole": _role_resource("ec2.amazonaws.com", "DataBucket"),
            "DBInstance": _db_instance(bad_db_id, "BadTrustRole"),
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["BadTrustRole", "Arn"]}}},
    }

    failed = _deploy_cfn_expect_rollback(
        ctx,
        json.dumps(bad_template),
        parameters={"MasterPassword": _DB_PASSWORD},
        timeout_s=1800.0,
    )
    assert failed["stack_status"] == "ROLLBACK_COMPLETE", (
        f"a DBInstance whose AssociatedRoles role RDS cannot assume should roll the stack back, "
        f"got {failed['stack_status']!r}"
    )
    db_failures = [r for r in failed["failed_resources"] if r["logical_id"] == "DBInstance"]
    assert db_failures, (
        f"expected the DBInstance resource itself to report CREATE_FAILED, "
        f"got failures on {[r['logical_id'] for r in failed['failed_resources']]!r}"
    )
    assert "AWS_ROLE_INTEGRATION" in db_failures[0]["reason"], (
        f"expected the DBInstance CREATE_FAILED reason to name the AWS_ROLE_INTEGRATION "
        f"association, got {db_failures[0]['reason']!r}"
    )

    # Effect absent, at an independent read: the rolled-back instance must not exist at RDS.
    rds = ctx.client("rds")
    try:
        rds.describe_db_instances(DBInstanceIdentifier=bad_db_id)
        raise AssertionError(
            f"expected DBInstanceNotFound for {bad_db_id!r} after stack rollback, but it exists"
        )
    except rds.exceptions.DBInstanceNotFoundFault as exc:
        message = exc.response["Error"].get("Message")
        assert message == f"DBInstance {bad_db_id} not found.", message

    # Positive control: the identical shape, but the role trusts rds.amazonaws.com. Must reach
    # CREATE_COMPLETE with the association settling ACTIVE.
    good_db_id = _xname(ctx, "db-good")
    good_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"MasterPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket"},
            "GoodTrustRole": _role_resource("rds.amazonaws.com", "DataBucket"),
            "DBInstance": _db_instance(good_db_id, "GoodTrustRole"),
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["GoodTrustRole", "Arn"]}}},
    }
    good = _deploy_cfn(
        ctx,
        json.dumps(good_template),
        parameters={"MasterPassword": _DB_PASSWORD},
        timeout_s=1800.0,
    )
    good_role_arn = good["outputs"]["RoleArn"]

    def _probe_good():
        desc = rds.describe_db_instances(DBInstanceIdentifier=good_db_id)["DBInstances"][0]
        by_arn = {r["RoleArn"]: r for r in desc.get("AssociatedRoles", [])}
        return by_arn.get(good_role_arn)

    positive_final = _poll_until(
        _probe_good,
        lambda r: r is not None and r.get("Status") in ("ACTIVE", "INVALID"),
        timeout_s=300.0,
        interval_s=10.0,
        description="correctly-trusted role association to reach a terminal status",
    )
    assert positive_final is not None, (
        f"expected the correctly-trusted role {good_role_arn!r} to appear in AssociatedRoles "
        f"for {good_db_id}, got none"
    )
    assert positive_final["Status"] == "ACTIVE", (
        f"correctly-trusted role should become ACTIVE (positive control), "
        f"got {positive_final['Status']!r}"
    )


# ===== helpers (self-contained) =====
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
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        failed = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatus')} {e.get('ResourceStatusReason', '')}"
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED")
        ]
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {failed}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _deploy_cfn_expect_rollback(
    ctx,
    template: str,
    *,
    stack_name: str | None = None,
    parameters: dict[str, str] | None = None,
    timeout_s: float = 1800.0,
) -> dict[str, Any]:
    """Like ``_deploy_cfn``, but the stack is EXPECTED to fail: returns the terminal status and
    the CREATE_FAILED resources instead of raising, so the caller can assert on the specific
    failure. Registers the same delete-stack teardown regardless of outcome."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    stack_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    failed_resources = [
        {
            "logical_id": e["LogicalResourceId"],
            "reason": e.get("ResourceStatusReason", ""),
        }
        for e in events
        if e.get("ResourceStatus", "").endswith("FAILED")
    ]
    return {"stack_name": name, "stack_status": stack_status, "failed_resources": failed_resources}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
