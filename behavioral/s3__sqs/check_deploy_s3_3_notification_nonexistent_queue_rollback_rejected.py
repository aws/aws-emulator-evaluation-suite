"""deploy-s3-3-notification-nonexistent-queue-rollback-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deploy-s3-3-notification-nonexistent-queue-rollback-rejected"

GROUP = "deploy-rollback-s3-notification"

SERVICES = ["s3", "sqs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:eventing",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A bucket notifying a nonexistent SQS queue fails destination validation and the stack rolls
    back to ROLLBACK_COMPLETE, deleting the earlier bucket. A control stack with a real queue and
    QueuePolicy completes and delivers ObjectCreated:Put, ruling out a malformed template.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    account, partition = _account_partition(ctx)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _await_deletes(ctx, stacks))  # registered first: runs last

    # ---- broken stack: nonexistent destination queue -------------------------------------
    bad_stack = ctx.unique_name("sim2real-s3-3-rb-")
    bad_a = ctx.unique_name("sim2real-s3-3-a-")
    bad_b = ctx.unique_name("sim2real-s3-3-b-")
    ghost_queue_arn = (
        f"arn:{partition}:sqs:{ctx.region}:{account}:"
        f"{ctx.unique_name('sim2real-s3-3-ghost-')}"
    )
    _create_stack(ctx, stacks, bad_stack, _broken_template(bad_a, bad_b, ghost_queue_arn), [bad_a, bad_b])
    bad = _wait_terminal(cfn, bad_stack, timeout_s=600.0)
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a stack whose BucketB notifies a nonexistent queue ended {bad['StackStatus']!r} "
        f"(reason {bad.get('StackStatusReason')!r}); expected ROLLBACK_COMPLETE"
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
    b_statuses = [e["ResourceStatus"] for e in events if e.get("LogicalResourceId") == "BucketB"]
    assert "CREATE_COMPLETE" not in b_statuses, (
        f"BucketB reached CREATE_COMPLETE despite an invalid destination: {b_statuses!r}"
    )
    a_statuses = [e["ResourceStatus"] for e in events if e.get("LogicalResourceId") == "BucketA"]
    assert "CREATE_COMPLETE" in a_statuses and "DELETE_COMPLETE" in a_statuses, (
        f"BucketA must be created and then deleted by the rollback; its events were {a_statuses!r}"
    )

    a_code = _head_bucket_code(s3, bad_a)
    assert a_code == "404", (
        f"after ROLLBACK_COMPLETE, HeadBucket on BucketA {bad_a!r} returned {a_code!r}; the "
        "rollback must have deleted the bucket it created (expected 404)"
    )
    b_code = _head_bucket_code(s3, bad_b)
    assert b_code == "404", (
        f"after ROLLBACK_COMPLETE, HeadBucket on BucketB {bad_b!r} returned {b_code!r}; a bucket "
        "whose destination failed validation must not exist (expected 404)"
    )

    # ---- positive control: real queue + queue policy ---------------------------------------
    good_stack = ctx.unique_name("sim2real-s3-3-ok-")
    good_a = ctx.unique_name("sim2real-s3-3-a-")
    good_b = ctx.unique_name("sim2real-s3-3-b-")
    queue_name = ctx.unique_name("sim2real-s3-3-q-")
    _create_stack(ctx, stacks, good_stack, _control_template(good_a, good_b, queue_name), [good_a, good_b])
    good = _wait_terminal(cfn, good_stack, timeout_s=600.0)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"control stack with a real queue and queue policy ended {good['StackStatus']!r} "
        f"(reason {good.get('StackStatusReason')!r}); expected CREATE_COMPLETE"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good.get("Outputs", [])}
    queue_url = outputs.get("QueueUrl")
    assert queue_url, f"control stack exported no QueueUrl; outputs were {outputs!r}"

    a_ok = _head_bucket_code(s3, good_a)
    assert a_ok == "200", f"control BucketA {good_a!r} HeadBucket returned {a_ok!r}, expected 200"

    key = "incoming/control-object.txt"
    s3.put_object(Bucket=good_b, Key=key, Body=b"control-payload")

    record, seen = _wait_for_object_record(sqs, queue_url, good_b, key, timeout_s=120.0)
    assert record is not None, (
        f"no ObjectCreated record for s3://{good_b}/{key} reached the queue within 120s; "
        f"bodies seen: {seen!r}"
    )
    assert record.get("eventSource") == "aws:s3", f"record eventSource was {record.get('eventSource')!r}"
    assert record.get("eventName") == "ObjectCreated:Put", (
        f"PutObject should be reported as ObjectCreated:Put, got {record.get('eventName')!r}"
    )
    assert record["s3"]["bucket"]["name"] == good_b, (
        f"record names bucket {record['s3']['bucket']['name']!r}, expected {good_b!r}"
    )
    assert record["s3"]["object"]["size"] == len(b"control-payload"), (
        f"record object size {record['s3']['object'].get('size')!r}, expected {len(b'control-payload')}"
    )



def _bucket_props(name: str) -> dict:
    return {
        "BucketName": name,
        "Tags": [{"Key": "sim2real", "Value": "deploy-s3-3"}],
    }


def _broken_template(bucket_a: str, bucket_b: str, ghost_queue_arn: str) -> str:
    props_b = _bucket_props(bucket_b)
    props_b["NotificationConfiguration"] = {
        "QueueConfigurations": [{"Event": "s3:ObjectCreated:*", "Queue": ghost_queue_arn}]
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "BucketA": {"Type": "AWS::S3::Bucket", "Properties": _bucket_props(bucket_a)},
            "BucketB": {"Type": "AWS::S3::Bucket", "DependsOn": "BucketA", "Properties": props_b},
        },
    })


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


def _account_partition(ctx: Any) -> tuple[str, str]:
    ident = ctx.client("sts").get_caller_identity()
    arn_fields = ident["Arn"].split(":")
    assert len(arn_fields) >= 6 and arn_fields[0] == "arn", f"unparseable caller ARN {ident['Arn']!r}"
    return ident["Account"], arn_fields[1]


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
    out.reverse()  # API returns newest first; chronological is easier to read in a message
    return out


def _head_bucket_code(s3: Any, bucket: str) -> str:
    try:
        resp = s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    return str(resp["ResponseMetadata"]["HTTPStatusCode"])


def _wait_for_object_record(
    sqs: Any, queue_url: str, bucket: str, key: str, *, timeout_s: float
) -> tuple[dict | None, list]:
    deadline = time.monotonic() + timeout_s
    seen: list = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10, VisibilityTimeout=60
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except ValueError:
                body = msg["Body"]
            seen.append(body if not isinstance(body, dict) else {
                "Event": body.get("Event"),
                "eventNames": [r.get("eventName") for r in body.get("Records", [])],
            })
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if not isinstance(body, dict) or body.get("Event") == "s3:TestEvent":
                continue
            for rec in body.get("Records", []):
                obj = rec.get("s3", {})
                if obj.get("bucket", {}).get("name") == bucket and obj.get("object", {}).get("key") == key:
                    return rec, seen
    return None, seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
