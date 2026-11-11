"""deploy-rds-role-trust-s3-service-mismatch-negative."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-role-trust-s3-service-mismatch-negative"
GROUP = "iac-s3-import-role"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack associating a role trusted by s3.amazonaws.com for s3Import rolls back with the RDS role
    integration reason and leaves no instance, while a role trusted by rds.amazonaws.com for the same
    feature reaches ACTIVE."""
    good_role_name = _xname(ctx, "s3import-role-control")
    good_bucket = _xname(ctx, "s3import-bkt-good")
    good_db_id = _xname(ctx, "s3import-db-good")
    _deploy_cfn(
        ctx,
        _s3_import_stack(ctx, good_bucket, good_role_name, "rds.amazonaws.com", good_db_id),
        timeout_s=1800.0,
    )

    rds = ctx.client("rds")

    def _role_status(db_id):
        inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        roles = inst.get("AssociatedRoles", [])
        return roles[0]["Status"] if roles else None

    good_status = _poll_until(
        lambda: _role_status(good_db_id),
        lambda s: s in {"ACTIVE", "INVALID"},
        timeout_s=600.0,
        interval_s=15.0,
        description=f"correctly-trusted AssociatedRole status settles for {good_db_id}",
    )
    assert good_status == "ACTIVE", (
        f"positive control (rds.amazonaws.com-trusted role) expected ACTIVE, got {good_status!r}"
    )

    # Negative: the SAME shape, only the trust principal differs. This must fail to deploy at
    # all -- never settle into an ACTIVE/INVALID DB instance.
    bad_role_name = _xname(ctx, "s3import-role-mismatch")
    bad_bucket = _xname(ctx, "s3import-bkt-bad")
    bad_db_id = _xname(ctx, "s3import-db-bad")
    bad = _deploy_cfn_allow_failure(
        ctx,
        _s3_import_stack(ctx, bad_bucket, bad_role_name, "s3.amazonaws.com", bad_db_id),
        timeout_s=600.0,
    )
    assert bad["status"] in {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"}, (
        f"expected the mismatched-trust stack to fail to deploy, got {bad['status']!r}"
    )
    db_failure = bad["failed_resources"].get("DBInstance", "")
    assert db_failure == _expected_role_integration_reason(db_failure), (
        f"expected RDS's synchronous role-trust rejection (AWS_ROLE_INTEGRATION) on the "
        f"DBInstance resource, got failed_resources={bad['failed_resources']!r}"
    )

    # Effect is ABSENT: since the stack never reached CREATE_COMPLETE, no DB instance for the
    # mismatched role was ever provisioned -- confirm via an independent read.
    try:
        rds.describe_db_instances(DBInstanceIdentifier=bad_db_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "DBInstanceNotFound", (
            f"expected DBInstanceNotFound for the never-provisioned {bad_db_id}, got {exc}"
        )
        message = exc.response["Error"].get("Message", "")
        assert message == f"DBInstance {bad_db_id} not found.", (
            f"unexpected DBInstanceNotFound message for {bad_db_id}: {message!r}"
        )
    else:
        raise AssertionError(
            f"DB instance {bad_db_id} unexpectedly exists despite the stack failing to deploy"
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


def _s3_import_stack(ctx: Any, bucket_name: str, role_name: str, trust_principal: str, db_id: str) -> str:
    """A bucket + a role (trusting `trust_principal`) + a DBInstance that associates that role
    for the s3Import feature at create time. Identical shape for both the good and the
    mismatched-trust stacks -- only `trust_principal` differs."""
    return json.dumps(
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
                                    "Principal": {"Service": trust_principal},
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
                    "DependsOn": ["ImportRole"],
                    "Properties": {
                        "DBInstanceIdentifier": db_id,
                        "Engine": "postgres",
                        "DBInstanceClass": "db.t3.micro",
                        "AllocatedStorage": "20",
                        "MasterUsername": "dbadmin",
                        "MasterUserPassword": _db_password(ctx),
                        "PubliclyAccessible": False,
                        "BackupRetentionPeriod": 0,
                        "AssociatedRoles": [
                            {
                                "FeatureName": "s3Import",
                                "RoleArn": {"Fn::GetAtt": ["ImportRole", "Arn"]},
                            }
                        ],
                        "DBSubnetGroupName": _network_db_subnet_group(ctx, ctx.client("rds")),
                    },
                },
            }
        }
    )


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
        timeout_s=900,
        interval_s=10.0,
        description=f"delete stack {stack_name}",
    )


def _create_stack_and_wait(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    """Create a CFN stack (template body str or Path); wait for a terminal status; register
    delete-stack-and-wait teardown. Returns {stack_name, stack_id, status, outputs, failed_resources}
    without judging the outcome -- callers decide whether CREATE_COMPLETE was required."""
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
    failed_resources = {
        e["LogicalResourceId"]: e.get("ResourceStatusReason", "no reason")
        for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
        if e["ResourceStatus"] in ("CREATE_FAILED", "UPDATE_FAILED")
    }
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {
        "stack_name": name,
        "stack_id": stack_id,
        "status": stack["StackStatus"],
        "status_reason": stack.get("StackStatusReason", "no reason given"),
        "outputs": outputs,
        "failed_resources": failed_resources,
    }


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    """Like `_create_stack_and_wait`, but raises unless the stack reaches CREATE_COMPLETE."""
    result = _create_stack_and_wait(
        ctx,
        template,
        stack_name=stack_name,
        parameters=parameters,
        capabilities=capabilities,
        timeout_s=timeout_s,
    )
    if result["status"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"Stack {result['stack_name']} ended in {result['status']}: "
            f"{result['status_reason']}; failed resources: {result['failed_resources']}"
        )
    return result


def _deploy_cfn_allow_failure(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    """Like `_create_stack_and_wait`, but also raises if the stack unexpectedly reaches
    CREATE_COMPLETE -- for callers that assert a deploy-time rejection is the expected outcome."""
    result = _create_stack_and_wait(
        ctx,
        template,
        stack_name=stack_name,
        parameters=parameters,
        capabilities=capabilities,
        timeout_s=timeout_s,
    )
    if result["status"] == "CREATE_COMPLETE":
        raise AssertionError(
            f"Stack {result['stack_name']} unexpectedly reached CREATE_COMPLETE; "
            "expected it to be rejected at deploy time"
        )
    return result


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
