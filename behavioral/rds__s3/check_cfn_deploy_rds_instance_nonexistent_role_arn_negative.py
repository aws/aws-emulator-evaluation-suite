"""cfn-deploy-rds-instance-nonexistent-role-arn-negative."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-instance-nonexistent-role-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real9!Behave"


def _real_role_resource(bucket_logical_id: str) -> dict[str, Any]:
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


def _db_instance_with_role_arn(db_id: str, role_arn, *, ctx) -> dict[str, Any]:
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    return {
        "Type": "AWS::RDS::DBInstance",
        "DeletionPolicy": "Delete",
        "Properties": {
            "DBInstanceIdentifier": db_id,
            "Engine": "postgres",
            "DBInstanceClass": "db.t3.micro",
            "AllocatedStorage": "20",
            "MasterUsername": "dbadmin",
            "MasterUserPassword": {"Ref": "AdminPassword"},
            "BackupRetentionPeriod": 0,
            "PubliclyAccessible": False,
            "MultiAZ": False,
            "DeletionProtection": False,
            "AssociatedRoles": [{"FeatureName": "s3Import", "RoleArn": role_arn}],
            "DBSubnetGroupName": subnet_group,
        },
    }


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose DBInstance names a nonexistent role in AssociatedRoles rolls back with an
    InvalidRequest "IAM role ARN value is invalid" reason and leaves no instance, while the same
    instance with a correctly trusted role reaches an ACTIVE association."""
    db_id = _xname(ctx, "db")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_role_name = _xname(ctx, "nonexistent-role")
    fake_role_arn = f"arn:aws:iam::{account_id}:role/{fake_role_name}"
    rds = ctx.client("rds")

    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AdminPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket"},
            "DBInstance": _db_instance_with_role_arn(db_id, fake_role_arn, ctx=ctx),
        },
    }
    bad_stack_name = _xname(ctx, "stk")
    bad_status, db_failures = _deploy_cfn_expect_rejection(
        ctx,
        json.dumps(bad_template),
        stack_name=bad_stack_name,
        parameters={"AdminPassword": _DB_PASSWORD},
        timeout_s=1200.0,
    )
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a DBInstance referencing a nonexistent IAM role ARN should roll the stack back, "
        f"got {bad_status!r}"
    )
    assert db_failures, (
        f"expected a CREATE_FAILED event on the DBInstance resource itself, got none among "
        f"{_stack_failure_events(ctx, bad_stack_name)!r}"
    )
    reason = db_failures[0]["reason"] or ""
    assert reason == _expected_role_integration_reason(reason), (
        f"expected the DBInstance failure to be RDS's AWS_ROLE_INTEGRATION refusal, got {reason!r}"
    )
    assert "HandlerErrorCode: InvalidRequest" in reason, (
        f"expected HandlerErrorCode: InvalidRequest (a validation rejection, not e.g. a "
        f"permissions or throttling failure), got {reason!r}"
    )

    # Independent read at the destination (RDS's own API, not CFN's): the instance was never
    # actually created -- the rejection happens before RDS persists a DBInstance record.
    try:
        rds.describe_db_instances(DBInstanceIdentifier=db_id)
        raise AssertionError(
            f"expected {db_id} to never exist after its create was rejected, but "
            f"describe_db_instances found it"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "DBInstanceNotFound", f"expected DBInstanceNotFound for {db_id}, got {code!r}"
        message = exc.response["Error"].get("Message", "")
        assert message == f"DBInstance {db_id} not found.", (
            f"unexpected DBInstanceNotFound message for {db_id}: {message!r}"
        )

    # Positive control: the SAME DBInstanceIdentifier, in a fresh stack, with a real and
    # correctly-trusted role, reaches CREATE_COMPLETE and the association reaches ACTIVE --
    # isolating the nonexistent ARN as the one broken thing above.
    good_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AdminPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DataBucket": {"Type": "AWS::S3::Bucket"},
            "RealRole": _real_role_resource("DataBucket"),
            "DBInstance": _db_instance_with_role_arn(db_id, {"Fn::GetAtt": ["RealRole", "Arn"]}, ctx=ctx),
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["RealRole", "Arn"]}}},
    }
    good_template["Resources"]["DBInstance"]["DependsOn"] = ["RealRole"]
    good_stack_name = _xname(ctx, "stk")
    good_result = _deploy_cfn(
        ctx,
        json.dumps(good_template),
        stack_name=good_stack_name,
        parameters={"AdminPassword": _DB_PASSWORD},
        timeout_s=1200.0,
    )
    real_role_arn = good_result["outputs"]["RoleArn"]

    def _probe_good():
        desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        by_arn = {r["RoleArn"]: r for r in desc.get("AssociatedRoles", [])}
        return by_arn.get(real_role_arn)

    positive_final = _poll_until(
        _probe_good,
        lambda r: r is not None and r.get("Status") in ("ACTIVE", "INVALID"),
        timeout_s=300.0,
        interval_s=10.0,
        description="real-role association to reach a terminal status",
    )
    assert positive_final is not None
    assert positive_final["Status"] == "ACTIVE", (
        f"real, correctly-trusted role should become ACTIVE (positive control), "
        f"got {positive_final['Status']!r}"
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


def _stack_failure_events(ctx, stack_name: str) -> list[dict[str, str]]:
    cfn = ctx.client("cloudformation")
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError as exc:
        return [{"error": str(exc)}]
    return [
        {
            "resource": e.get("LogicalResourceId"),
            "status": e.get("ResourceStatus"),
            "reason": e.get("ResourceStatusReason"),
        }
        for e in events
        if e.get("ResourceStatus", "").endswith("FAILED")
    ]


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


def _deploy_cfn_expect_rejection(
    ctx,
    template,
    *,
    stack_name: str,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> tuple[str, list[dict[str, str]]]:
    """Like _deploy_cfn but expects the stack to be REJECTED (never CREATE_COMPLETE). Returns
    (final_status, [failed DBInstance events]); raises if the stack unexpectedly completes."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )
    assert final_status != "CREATE_COMPLETE", (
        f"expected stack {stack_name} to be rejected (nonexistent role ARN) but it reached "
        f"CREATE_COMPLETE -- the target accepted an IAM role ARN that does not exist"
    )
    failed = [e for e in _stack_failure_events(ctx, stack_name) if e["resource"] == "DBInstance"]
    return final_status, failed


def _expected_role_integration_reason(reason: str) -> str:
    """The exact CFN DBInstance CREATE_FAILED reason for RDS's AWS_ROLE_INTEGRATION refusal,
    built around the per-request RDS Request ID, SDK attempt count and CFN RequestToken read
    from the reason."""
    request_id = re.search(r"Request ID: ([0-9A-Za-z-]+)\)", reason)
    attempts = re.search(r"\(SDK Attempt Count: ([0-9]+)\)", reason)
    token = re.search(r"RequestToken: ([0-9A-Za-z-]+),", reason)
    return (
        'Resource handler returned message: "IAM role ARN value is invalid or does not include '
        "the required permissions for: AWS_ROLE_INTEGRATION (Service: Rds, Status Code: 400, "
        f"Request ID: {request_id.group(1) if request_id else '<missing>'}) "
        f'(SDK Attempt Count: {attempts.group(1) if attempts else "<missing>"})" '
        f"(RequestToken: {token.group(1) if token else '<missing>'}, "
        "HandlerErrorCode: InvalidRequest)"
    )


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
