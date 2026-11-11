"""integration-lifecycle-state-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A zero-ETL/S3-event CreateIntegration transitions creating -> active, is
    listed by DescribeIntegrations while it exists, and DeleteIntegration removes
    it entirely (subsequent DescribeIntegrations 404s on the same ARN)."""
    redshift = ctx.client("redshift")
    s3 = ctx.client("s3")
    rs_serverless = ctx.client("redshift-serverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket_name = ctx.unique_name("sim2real-rsintg-").lower()
    # us-east-1 literal: S3-specific CreateBucket quirk (LocationConstraint is
    # rejected for that region), not a pin of the check's own region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-behavioral", "Value": CHECK}]},
    )
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAutoCopyPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": [
                    "s3:GetBucketNotification",
                    "s3:PutBucketNotification",
                    "s3:GetBucketLocation",
                ],
                "Resource": bucket_arn,
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:redshift:{region}:{account_id}:integration:*"
                    },
                    "StringEquals": {"aws:SourceAccount": account_id},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    namespace_name = ctx.unique_name("sim2real-rsns-").lower()
    ns = rs_serverless.create_namespace(
        namespaceName=namespace_name,
        tags=[{"key": "sim2real-behavioral", "value": CHECK}],
    )["namespace"]
    ctx.on_cleanup(lambda: _delete_namespace(rs_serverless, namespace_name))
    namespace_arn = ns["namespaceArn"]
    _poll_namespace_available(ctx, rs_serverless, namespace_name, timeout_s=300.0)

    # A namespace alone has no compute bound to it and CreateIntegration cannot
    # resolve it as a target warehouse (IntegrationTargetNotFoundFault); a
    # workgroup is required, and zero-ETL integrations additionally require
    # case-sensitive identifiers enabled on it.
    workgroup_name = ctx.unique_name("sim2real-rswg-").lower()
    rs_serverless.create_workgroup(
        workgroupName=workgroup_name,
        namespaceName=namespace_name,
        baseCapacity=8,
        tags=[{"key": "sim2real-behavioral", "value": CHECK}],
        subnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_workgroup(rs_serverless, workgroup_name))
    _poll_workgroup_available(ctx, rs_serverless, workgroup_name, timeout_s=600.0)
    rs_serverless.update_workgroup(
        workgroupName=workgroup_name,
        configParameters=[
            {"parameterKey": "enable_case_sensitive_identifier", "parameterValue": "true"}
        ],
    )
    _poll_workgroup_available(ctx, rs_serverless, workgroup_name, timeout_s=600.0)

    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": bucket_arn,
                        "aws:SourceAccount": account_id,
                    }
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": bucket_arn,
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    redshift.put_resource_policy(
        ResourceArn=namespace_arn, Policy=json.dumps(resource_policy)
    )
    ctx.on_cleanup(lambda: _delete_resource_policy(redshift, namespace_arn))

    integration_name = ctx.unique_name("sim2realintg").replace("-", "")
    created = redshift.create_integration(
        IntegrationName=integration_name,
        SourceArn=bucket_arn,
        TargetArn=namespace_arn,
        TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    integration_arn = created["IntegrationArn"]
    assert created["Status"] in ("creating", "active"), (
        f"expected CreateIntegration Status in ('creating', 'active'), got "
        f"{created['Status']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_integration(redshift, integration_arn))

    final = _poll_integration_status(
        ctx, redshift, integration_arn, {"active"}, timeout_s=600.0
    )
    assert final["Status"] == "active", (
        f"expected integration to reach 'active', got {final['Status']!r}"
    )
    assert final["SourceArn"] == bucket_arn, (
        f"expected SourceArn {bucket_arn!r}, got {final['SourceArn']!r}"
    )
    assert final["TargetArn"] == namespace_arn, (
        f"expected TargetArn {namespace_arn!r}, got {final['TargetArn']!r}"
    )

    listed = redshift.describe_integrations(IntegrationArn=integration_arn)[
        "Integrations"
    ]
    assert len(listed) == 1 and listed[0]["IntegrationArn"] == integration_arn, (
        f"expected exactly one integration with ARN {integration_arn!r}, got {listed!r}"
    )

    redshift.delete_integration(IntegrationArn=integration_arn)

    code, message = _poll_until_gone(ctx, redshift, integration_arn, timeout_s=300.0)
    assert code == "IntegrationNotFoundFault", (
        f"expected DescribeIntegrations to 404 with 'IntegrationNotFoundFault' "
        f"after delete, got {code!r}"
    )
    assert message == "The requested integration doesn't exist.", (
        f"unexpected IntegrationNotFoundFault message {message!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_workgroup_available(ctx, rs_serverless, workgroup_name, timeout_s):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = rs_serverless.get_workgroup(workgroupName=workgroup_name)[
                "workgroup"
            ]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(1)
            continue
        if last == "AVAILABLE":
            return
        if last in ("FAILED", "DELETING"):
            raise AssertionError(f"workgroup {workgroup_name} entered {last}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"workgroup {workgroup_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(
        f"workgroup {workgroup_name} never reached AVAILABLE within {timeout_s}s; "
        f"last observed: {last}"
    )


def _delete_workgroup(rs_serverless, workgroup_name, timeout_s=900.0):
    """Delete the workgroup and wait until it is gone: DeleteNamespace refuses with
    ConflictException while the namespace still has a workgroup. A workgroup still busy with
    the integration's teardown refuses with ConflictException, which is retried, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rs_serverless.delete_workgroup(workgroupName=workgroup_name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            rs_serverless.get_workgroup(workgroupName=workgroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"workgroup {workgroup_name} still present {timeout_s}s after DeleteWorkgroup")


def _poll_namespace_available(ctx, rs_serverless, namespace_name, timeout_s):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rs_serverless.get_namespace(namespaceName=namespace_name)["namespace"][
            "status"
        ]
        if last == "AVAILABLE":
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"namespace {namespace_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(
        f"namespace {namespace_name} never reached AVAILABLE within {timeout_s}s; "
        f"last observed: {last}"
    )


def _poll_integration_status(ctx, redshift, integration_arn, terminal_statuses, timeout_s):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_integrations(IntegrationArn=integration_arn)[
            "Integrations"
        ][0]
        if last["Status"] in terminal_statuses or last["Status"] in (
            "failed",
            "needs_attention",
        ):
            return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"integration {integration_arn} in {terminal_statuses}: the run budget ended first; not graded")
    raise AssertionError(
        f"integration {integration_arn} never reached {terminal_statuses} within "
        f"{timeout_s}s; last observed: {last}"
    )


def _poll_until_gone(ctx, redshift, integration_arn, timeout_s):
    """Poll DescribeIntegrations until it rejects the ARN as not found; return that
    (Error.Code, Error.Message). Still being listed at the deadline raises."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            redshift.describe_integrations(IntegrationArn=integration_arn)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "IntegrationNotFoundFault":
                return error.get("Code"), error.get("Message")
            raise
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"integration {integration_arn} gone: the run budget ended first; not graded")
    raise AssertionError(
        f"integration {integration_arn} was still described {timeout_s}s after DeleteIntegration"
    )


def _safe_delete_integration(redshift, integration_arn):
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "IntegrationNotFoundFault",
            "IntegrationConflictStateFault",
        ):
            raise


def _delete_resource_policy(redshift, resource_arn):
    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundFault",):
            raise


def _delete_namespace(rs_serverless, namespace_name):
    try:
        rs_serverless.delete_namespace(namespaceName=namespace_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
