"""deploy-s3-3-notification-queue-without-policy-rollback-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deploy-s3-3-notification-queue-without-policy-rollback-rejected"

GROUP = "deploy-rollback-s3-notification"

SERVICES = ["s3", "sqs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:eventing",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A queue whose policy does not grant s3.amazonaws.com SendMessage fails S3 destination
    validation: the stack rolls back, neither bucket survives, and no message about the failed
    bucket reaches the queue, while the same stack plus a QueuePolicy completes and delivers.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _await_deletes(ctx, stacks))  # registered first: runs last

    queue_name = ctx.unique_name("sim2real-s3-3-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": "deploy-s3-3"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn", "Policy"])
    assert "Policy" not in queue_arn["Attributes"], (
        f"a freshly created queue must carry no resource policy, got {queue_arn['Attributes'].get('Policy')!r}"
    )
    queue_arn = queue_arn["Attributes"]["QueueArn"]

    # ---- broken stack: real queue, no policy ---------------------------------------------
    bad_stack = ctx.unique_name("sim2real-s3-3-np-")
    bad_a = ctx.unique_name("sim2real-s3-3-a-")
    bad_b = ctx.unique_name("sim2real-s3-3-b-")
    _create_stack(ctx, stacks, bad_stack, _template(bad_a, bad_b, queue_arn, with_policy=False), [bad_a, bad_b])
    bad = _wait_terminal(cfn, bad_stack, timeout_s=600.0)
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a stack whose BucketB notifies a queue with no s3.amazonaws.com grant ended "
        f"{bad['StackStatus']!r} (reason {bad.get('StackStatusReason')!r}); expected ROLLBACK_COMPLETE"
    )
    events = _events(cfn, bad_stack)
    b_failed = [
        e for e in events
        if e.get("LogicalResourceId") == "BucketB" and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert len(b_failed) == 1, (
        f"expected exactly one CREATE_FAILED event for BucketB, got "
        f"{[(e.get('ResourceStatus'), e.get('ResourceStatusReason')) for e in events if e.get('LogicalResourceId') == 'BucketB']!r}"
    )
    reason = b_failed[0].get("ResourceStatusReason") or ""
    assert "Unable to validate the following destination configurations" in reason, (
        f"BucketB's CREATE_FAILED reason does not name the destination validation failure: {reason!r}"
    )
    a_statuses = [e["ResourceStatus"] for e in events if e.get("LogicalResourceId") == "BucketA"]
    assert "CREATE_COMPLETE" in a_statuses and "DELETE_COMPLETE" in a_statuses, (
        f"BucketA must be created and then deleted by the rollback; its events were {a_statuses!r}"
    )
    for name, bucket in (("BucketA", bad_a), ("BucketB", bad_b)):
        code = _head_bucket_code(s3, bucket)
        assert code == "404", (
            f"after ROLLBACK_COMPLETE, HeadBucket on {name} {bucket!r} returned {code!r}; expected 404"
        )

    # ---- repair exactly one thing: add the queue policy ------------------------------------
    good_stack = ctx.unique_name("sim2real-s3-3-wp-")
    good_a = ctx.unique_name("sim2real-s3-3-a-")
    good_b = ctx.unique_name("sim2real-s3-3-b-")
    _create_stack(
        ctx, stacks, good_stack, _template(good_a, good_b, queue_arn, queue_url=queue_url, with_policy=True),
        [good_a, good_b],
    )
    good = _wait_terminal(cfn, good_stack, timeout_s=600.0)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"the same stack plus a QueuePolicy ended {good['StackStatus']!r} "
        f"(reason {good.get('StackStatusReason')!r}); expected CREATE_COMPLETE"
    )

    key = "incoming/repaired.txt"
    s3.put_object(Bucket=good_b, Key=key, Body=b"repaired")
    record, bodies = _wait_for_object_record(sqs, queue_url, good_b, key, timeout_s=120.0)
    assert record is not None, (
        f"no ObjectCreated record for s3://{good_b}/{key} reached the queue within 120s; "
        f"bodies seen: {_summ(bodies)!r}"
    )
    assert record.get("eventName") == "ObjectCreated:Put", (
        f"PutObject should be reported as ObjectCreated:Put, got {record.get('eventName')!r}"
    )
    test_events = [b for b in bodies if isinstance(b, dict) and b.get("Event") == "s3:TestEvent"]
    assert any(b.get("Bucket") == good_b for b in test_events), (
        f"the repaired BucketB {good_b!r} should have sent its s3:TestEvent to the queue; "
        f"bodies seen: {_summ(bodies)!r}"
    )
    leaked = [b for b in bodies if _mentions(b, bad_b)]
    assert leaked == [], (
        f"the queue received message(s) about the rolled-back bucket {bad_b!r} even though S3 "
        f"refused that destination: {_summ(leaked)!r}"
    )


# ===== helpers =====

def _bucket_props(name: str) -> dict:
    return {
        "BucketName": name,
        "Tags": [{"Key": "sim2real", "Value": "deploy-s3-3"}],
    }


def _template(bucket_a: str, bucket_b: str, queue_arn: str, *, with_policy: bool,
              queue_url: str | None = None) -> str:
    props_b = _bucket_props(bucket_b)
    props_b["NotificationConfiguration"] = {
        "QueueConfigurations": [{"Event": "s3:ObjectCreated:*", "Queue": queue_arn}]
    }
    resources: dict = {
        "BucketA": {"Type": "AWS::S3::Bucket", "Properties": _bucket_props(bucket_a)},
        "BucketB": {"Type": "AWS::S3::Bucket", "DependsOn": ["BucketA"], "Properties": props_b},
    }
    if with_policy:
        # Retain: the queue belongs to the check, not the stack, and is deleted by the check's
        # own cleanup; without Retain that delete would race CloudFormation removing this policy.
        resources["QueuePolicy"] = {
            "Type": "AWS::SQS::QueuePolicy",
            "DeletionPolicy": "Retain",
            "Properties": {
                "Queues": [queue_url],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "s3.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": queue_arn,
                        "Condition": {
                            "ArnLike": {
                                "aws:SourceArn": {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket_b}"}
                            },
                            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                        },
                    }],
                },
            },
        }
        resources["BucketB"]["DependsOn"] = ["BucketA", "QueuePolicy"]
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


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


def _events(cfn: Any, stack_name: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page.get("StackEvents", []))
    out.reverse()
    return out


def _head_bucket_code(s3: Any, bucket: str) -> str:
    try:
        resp = s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    return str(resp["ResponseMetadata"]["HTTPStatusCode"])


def _mentions(body: Any, bucket: str) -> bool:
    if not isinstance(body, dict):
        return bucket in str(body)
    if body.get("Bucket") == bucket:
        return True
    return any(r.get("s3", {}).get("bucket", {}).get("name") == bucket for r in body.get("Records", []))


def _summ(bodies: list) -> list:
    out = []
    for b in bodies:
        if isinstance(b, dict):
            out.append({
                "Event": b.get("Event"),
                "Bucket": b.get("Bucket"),
                "records": [
                    (r.get("eventName"), r.get("s3", {}).get("bucket", {}).get("name"))
                    for r in b.get("Records", [])
                ],
            })
        else:
            out.append(b)
    return out


def _wait_for_object_record(
    sqs: Any, queue_url: str, bucket: str, key: str, *, timeout_s: float
) -> tuple[dict | None, list]:
    """Drain the queue until the ObjectCreated record for bucket/key arrives; return it and every body."""
    deadline = time.monotonic() + timeout_s
    bodies: list = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10, VisibilityTimeout=60
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except ValueError:
                body = msg["Body"]
            bodies.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        for body in bodies:
            if not isinstance(body, dict) or body.get("Event") == "s3:TestEvent":
                continue
            for rec in body.get("Records", []):
                obj = rec.get("s3", {})
                if obj.get("bucket", {}).get("name") == bucket and obj.get("object", {}).get("key") == key:
                    return rec, bodies
    return None, bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
