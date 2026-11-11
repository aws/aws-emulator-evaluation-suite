"""list-insights-data-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-insights-data-permission-denied"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInsightsData for a role whose policy explicitly denies it raises AccessDeniedException
    with the exact explicit-deny message; replacing the policy without the Deny lets the identical
    assumed-role session succeed."""
    # OperationNotPermittedException needs an organization trail plus a second member account;
    # an explicit IAM Deny is the reachable form of insufficient permission for this operation.
    ct = ctx.client("cloudtrail")
    trail = _create_minimal_trail(ctx)
    ct.put_insight_selectors(
        TrailName=trail["name"],
        InsightSelectors=[{"InsightType": "ApiCallRateInsight", "EventCategories": ["Management"]}],
    )

    role_arn, role_name, policy_name = _create_denied_role(ctx)
    denied_session_name = ctx.unique_name("sim2real-ct-sess-")[:64]
    denied_client = _wait_for_assumable_client(ctx, role_arn, "cloudtrail", denied_session_name)

    def _call_as_denied_principal():
        denied_client.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")

    code, message = _wait_for_error(_call_as_denied_principal, "AccessDeniedException", timeout_s=45.0)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{denied_session_name}"
    assert message == (
        f"User: {session_arn} is not authorized to perform: cloudtrail:ListInsightsData on "
        f"resource: {trail['arn']} with an explicit deny in an identity-based policy"
    ), message

    iam = ctx.client("iam")
    attached_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
    assert any(
        stmt.get("Effect") == "Deny" and "cloudtrail:ListInsightsData" in stmt.get("Action", [])
        for stmt in attached_doc["Statement"]
    ), f"expected {policy_name!r} to still carry the Deny statement while the call is rejected; got {attached_doc!r}"

    # Replace rather than delete the policy: deleting it would also drop the Allow grants,
    # so success could not be tied to removing the Deny statement.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_allow_policy_document())
    )
    restored_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
    assert not any(stmt.get("Effect") == "Deny" for stmt in restored_doc["Statement"]), (
        f"expected the Deny statement to be gone from {policy_name!r} after PutRolePolicy; got {restored_doc!r}"
    )

    def _call_as_restored_principal():
        return denied_client.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")

    restored = _wait_for_success(_call_as_restored_principal, timeout_s=45.0)
    assert isinstance(restored.get("Events"), list), f"Events is not a list: {restored.get('Events')!r}"

    # Additional control: the very same call, with normal credentials, succeeds too.
    resp = ct.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")
    assert isinstance(resp.get("Events"), list)



def _wait_for_error(fn, expected_code: str, *, timeout_s: float, interval_s: float = 3.0) -> tuple[str, str | None]:
    """Poll until fn() raises expected_code and return its (Code, Message).

    A new Deny policy takes seconds to propagate, so early calls may succeed or fail otherwise."""
    deadline = time.monotonic() + timeout_s
    last: object = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == expected_code:
                return err["Code"], err.get("Message")
            last = err
        time.sleep(interval_s)
    raise AssertionError(f"call never failed with {expected_code} within {timeout_s}s; last outcome {last!r}")


def _wait_for_success(fn, *, timeout_s: float, interval_s: float = 3.0):
    """Poll until fn() stops raising, tolerating IAM policy-removal propagation lag."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call never succeeded within {timeout_s}s after removing the deny policy: {last_exc}")


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """CloudTrail writes into the trail bucket, so empty it before DeleteBucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _create_minimal_trail(ctx) -> dict[str, Any]:
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-ct-trail-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    name = ctx.unique_name("sim2real-ct-trail-")
    resp = ct.create_trail(Name=name, S3BucketName=bucket, IsMultiRegionTrail=False)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=name))
    ct.add_tags(ResourceId=resp["TrailARN"], TagsList=[{"Key": "sim2real", "Value": CHECK}])
    return {"name": name, "arn": resp["TrailARN"], "bucket": bucket}


def _create_denied_role(ctx) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ct-denied-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = created["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "deny-list-insights-data"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_deny_policy_document())
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn, role_name, policy_name


def _deny_policy_document() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["cloudtrail:DescribeTrails", "cloudtrail:ListChannels"],
                "Resource": "*",
            },
            {"Effect": "Deny", "Action": "cloudtrail:ListInsightsData", "Resource": "*"},
        ],
    }


def _allow_policy_document() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["cloudtrail:DescribeTrails", "cloudtrail:ListChannels", "cloudtrail:ListInsightsData"],
                "Resource": "*",
            },
        ],
    }


def _wait_for_assumable_client(ctx, role_arn: str, service: str, session_name: str, *, timeout_s: float = 30.0):
    sts = ctx.client("sts")

    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return ctx.client(service, creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"role {role_arn} never became assumable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
