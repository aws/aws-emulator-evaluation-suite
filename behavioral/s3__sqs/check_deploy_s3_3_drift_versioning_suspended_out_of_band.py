"""deploy-s3-3-drift-versioning-suspended-out-of-band."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deploy-s3-3-drift-versioning-suspended-out-of-band"

GROUP = "deploy-rollback-s3-notification"

SERVICES = ["s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Suspending versioning out of band on a CFN-managed bucket makes DetectStackDrift report only
    that bucket MODIFIED at /VersioningConfiguration/Status (Enabled vs Suspended), and PutObject
    returns a VersionId before the suspension but none after it.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _await_deletes(ctx, stacks))  # registered first: runs last

    stack = ctx.unique_name("sim2real-s3-3-dr-")
    bucket_a = ctx.unique_name("sim2real-s3-3-a-")
    bucket_b = ctx.unique_name("sim2real-s3-3-b-")
    queue_name = ctx.unique_name("sim2real-s3-3-q-")
    _create_stack(ctx, stacks, stack, _control_template(bucket_a, bucket_b, queue_name), [bucket_a, bucket_b])
    desc = _wait_terminal(cfn, stack, timeout_s=600.0)
    assert desc["StackStatus"] == "CREATE_COMPLETE", (
        f"control stack ended {desc['StackStatus']!r} (reason {desc.get('StackStatusReason')!r}); "
        "expected CREATE_COMPLETE"
    )

    before = s3.put_object(Bucket=bucket_b, Key="k.txt", Body=b"before-suspend")
    before_vid = str(before.get("VersionId"))
    assert len(before_vid) > 4 and before_vid != "null", (
        f"BucketB was deployed with versioning Enabled but PutObject returned VersionId "
        f"{before.get('VersionId')!r}"
    )

    # Baseline: an untouched stack is IN_SYNC.
    base = _detect_drift(cfn, stack)
    assert base["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly deployed, untouched stack reported drift {base['StackDriftStatus']!r} "
        f"({base.get('DriftedStackResourceCount')!r} drifted resources); expected IN_SYNC"
    )

    # Out-of-band change through S3, not CloudFormation.
    s3.put_bucket_versioning(Bucket=bucket_b, VersioningConfiguration={"Status": "Suspended"})
    live = s3.get_bucket_versioning(Bucket=bucket_b).get("Status")
    assert live == "Suspended", f"GetBucketVersioning after suspension returned {live!r}"

    after = s3.put_object(Bucket=bucket_b, Key="k.txt", Body=b"after-suspend")
    # Real AWS omits x-amz-version-id on a PutObject into a Suspended bucket.
    assert "VersionId" not in after, (
        f"a PutObject into a Suspended bucket returned VersionId {after.get('VersionId')!r}; real "
        "AWS returns no version id header there"
    )
    versions = [
        v for v in s3.list_object_versions(Bucket=bucket_b, Prefix="k.txt").get("Versions", [])
        if v["Key"] == "k.txt"
    ]
    by_id = {v["VersionId"]: v["IsLatest"] for v in versions}
    assert by_id == {before_vid: False, "null": True}, (
        f"after suspension the key should hold the pre-suspension version plus a latest 'null' "
        f"version; ListObjectVersions reported {by_id!r}"
    )

    drift = _detect_drift(cfn, stack)
    assert drift["StackDriftStatus"] == "DRIFTED", (
        f"after suspending versioning out of band, DetectStackDrift reported "
        f"{drift['StackDriftStatus']!r}; expected DRIFTED"
    )
    assert drift.get("DriftedStackResourceCount") == 1, (
        f"exactly one resource (BucketB) was changed, but DriftedStackResourceCount is "
        f"{drift.get('DriftedStackResourceCount')!r}"
    )

    drifts = _resource_drifts(cfn, stack)
    status = {d["LogicalResourceId"]: d["StackResourceDriftStatus"] for d in drifts}
    assert status.get("BucketB") == "MODIFIED", f"BucketB drift status {status.get('BucketB')!r}; all: {status!r}"
    assert status.get("BucketA") == "IN_SYNC", f"untouched BucketA drift status {status.get('BucketA')!r}"
    assert status.get("Queue") == "IN_SYNC", f"untouched Queue drift status {status.get('Queue')!r}"

    b_drift = next(d for d in drifts if d["LogicalResourceId"] == "BucketB")
    diffs = b_drift.get("PropertyDifferences", [])
    paths = [p.get("PropertyPath") for p in diffs]
    assert paths == ["/VersioningConfiguration/Status"], (
        f"BucketB's PropertyDifferences should name only /VersioningConfiguration/Status, got {paths!r}"
    )
    diff = diffs[0]
    assert diff.get("ExpectedValue") == "Enabled" and diff.get("ActualValue") == "Suspended", (
        f"expected Enabled -> Suspended, got ExpectedValue={diff.get('ExpectedValue')!r} "
        f"ActualValue={diff.get('ActualValue')!r}"
    )
    assert diff.get("DifferenceType") == "NOT_EQUAL", f"DifferenceType was {diff.get('DifferenceType')!r}"

    stack_info = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("DriftInformation", {})
    assert stack_info.get("StackDriftStatus") == "DRIFTED", (
        f"DescribeStacks DriftInformation still reads {stack_info.get('StackDriftStatus')!r} after detection"
    )


# ===== helpers =====

def _bucket_props(name: str) -> dict:
    return {
        "BucketName": name,
        "Tags": [{"Key": "sim2real", "Value": "deploy-s3-3"}],
    }


def _control_template(bucket_a: str, bucket_b: str, queue_name: str) -> str:
    props_b = _bucket_props(bucket_b)
    props_b["VersioningConfiguration"] = {"Status": "Enabled"}
    props_b["NotificationConfiguration"] = {
        "QueueConfigurations": [
            {"Event": "s3:ObjectCreated:*", "Queue": {"Fn::GetAtt": ["Queue", "Arn"]}}
        ]
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "BucketA": {"Type": "AWS::S3::Bucket", "Properties": _bucket_props(bucket_a)},
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "Tags": [{"Key": "sim2real", "Value": "deploy-s3-3"}],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {
                                "ArnLike": {
                                    "aws:SourceArn": {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket_b}"}
                                },
                                "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                            },
                        }],
                    },
                },
            },
            "BucketB": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": ["BucketA", "QueuePolicy"],
                "Properties": props_b,
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    })


def _create_stack(
    ctx: Any, stacks: list[str], stack_name: str, template: str, buckets: list[str]
) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "deploy-s3-3"}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name, buckets))
    stacks.append(stack_name)


def _teardown_stack(ctx: Any, stack_name: str, buckets: list[str]) -> None:
    """Empty the stack's buckets, then issue the delete without waiting for it.

    _await_deletes (registered first, so it runs last) waits for every delete to finish.
    """
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    for bucket in buckets:
        try:
            _empty_bucket(s3, bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    try:
        cfn.delete_stack(StackName=stack_name)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"stack {stack_name} delete_stack was refused: {exc}") from exc


def _await_deletes(ctx: Any, stacks: list[str], *, budget_s: float = 600.0) -> None:
    """Last net: wait for this check's stacks to be deleted; raise on any that failed or did not finish."""
    cfn = ctx.client("cloudformation")
    failed: list[str] = []
    pending = list(stacks)
    deadline = time.monotonic() + budget_s
    while pending and time.monotonic() < deadline:
        still = []
        for name in pending:
            try:
                status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                    continue  # gone: describe_stacks by name does not resolve a deleted stack
                raise
            if status == "DELETE_FAILED":
                failed.append(f"stack {name} is DELETE_FAILED")
            elif status != "DELETE_COMPLETE":
                still.append(name)
        pending = still
        if pending:
            time.sleep(2)
    failed += [f"stack {name} still deleting after {budget_s}s" for name in pending]
    if failed:
        raise RuntimeError("; ".join(failed))


def _empty_bucket(s3: Any, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000], "Quiet": True})


def _wait_terminal(cfn: Any, stack_name: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        if not last["StackStatus"].endswith("_IN_PROGRESS"):
            return last
        time.sleep(5)
    raise AssertionError(
        f"stack {stack_name} still {last and last['StackStatus']!r} after {timeout_s}s"
    )


def _detect_drift(cfn: Any, stack_name: str, *, timeout_s: float = 300.0) -> dict:
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id} ended {last['DetectionStatus']!r}: "
                f"{last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(3)
    raise AssertionError(f"drift detection {detection_id} still in progress after {timeout_s}s: {last!r}")


def _resource_drifts(cfn: Any, stack_name: str) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {"StackName": stack_name}
    while True:
        page = cfn.describe_stack_resource_drifts(**kwargs)
        out.extend(page.get("StackResourceDrifts", []))
        token = page.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
