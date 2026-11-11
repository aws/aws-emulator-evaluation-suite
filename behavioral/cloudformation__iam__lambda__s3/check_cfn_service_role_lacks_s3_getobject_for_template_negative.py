"""cfn-service-role-lacks-s3-getobject-for-template-negative."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-service-role-lacks-s3-getobject-for-template-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """CreateStack from a private-bucket TemplateURL with a no-S3 service role reaches CREATE_COMPLETE (the caller's
    credentials read the template); CreateChangeSet with that role and a missing-bucket TemplateURL is refused with
    ValidationError "S3 error: The specified bucket does not exist ..." and creates no stack."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)
    key = "templates/service-role.json"
    s3.put_object(Bucket=bucket, Key=key, Body=_TEMPLATE.encode("utf-8"))
    template_url = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{key}"

    # The service role may manage the stack's SNS topic but has no S3 permissions at all.
    role_arn = _create_cfn_service_role(ctx, extra_statements=[])
    stack_name = _xname(ctx, "stk-nos3")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    # A just-created role answers ValidationError "Role ... is invalid" until IAM propagates it.
    _retry_create_stack_until_role_usable(
        cfn, StackName=stack_name, TemplateURL=template_url, RoleARN=role_arn, Tags=_xsvc_tags_kv(),
    )
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"stack {stack_name} terminal",
    )
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status}"

    # Control: the template fetch is real, so a target that accepts any template source fails here.
    missing_url = f"https://{_xname(ctx, 'missing')}.s3.{ctx.region}.amazonaws.com/{key}"
    refused_stack = _xname(ctx, "stk-missing")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, refused_stack))
    got = _error(lambda: cfn.create_change_set(
        StackName=refused_stack, ChangeSetName="cs-" + uuid.uuid4().hex[:12], ChangeSetType="CREATE",
        TemplateURL=missing_url, RoleARN=role_arn, Tags=_xsvc_tags_kv(),
    ))
    want = ("ValidationError", "S3 error: The specified bucket does not exist" + _S3_HELP)
    assert got == want, f"{missing_url!r}: expected {want!r}, got {got!r}"
    got = _error(lambda: cfn.describe_stacks(StackName=refused_stack))
    want = ("ValidationError", f"Stack with id {refused_stack} does not exist")
    assert got == want, f"the refused change set must create no stack: expected {want!r}, got {got!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

#: CloudFormation appends this pointer to the S3 error it relays for a TemplateURL.
_S3_HELP = "\nFor more information check http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html"


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn()`` raises; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _retry_create_stack_until_role_usable(cfn, *, timeout_s: float = 60.0, **create_kwargs) -> None:
    """CreateStack raises ValidationError("Role ... is invalid") for a role that CloudFormation
    cannot yet assume because IAM's create_role/put_role_policy just returned and the new role
    has not propagated. Retry the SAME call (not just the role creation) until it is usable."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            cfn.create_stack(**create_kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "invalid" in str(exc).lower():
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"role {create_kwargs['RoleARN']} never became usable by CloudFormation: {last_exc}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    to_delete: list[dict[str, str]] = []
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []):
            to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
    for i in range(0, len(to_delete), 1000):
        batch = to_delete[i : i + 1000]
        if batch:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_cfn_service_role(ctx, extra_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "cfn-role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "sns:CreateTopic",
                "sns:DeleteTopic",
                "sns:GetTopicAttributes",
                "sns:SetTopicAttributes",
                "sns:TagResource",
            ],
            "Resource": "*",
        }
    ] + extra_statements
    policy_name = _xname(ctx, "cfn-role-policy")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
