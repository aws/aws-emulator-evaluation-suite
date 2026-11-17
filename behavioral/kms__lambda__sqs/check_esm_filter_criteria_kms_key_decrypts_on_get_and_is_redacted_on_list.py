"""esm-filter-criteria-kms-key-decrypts-on-get-and-is-redacted-on-list."""
from __future__ import annotations

import json
import time
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-filter-criteria-kms-key-decrypts-on-get-and-is-redacted-on-list"
GROUP = "event-filtering"
SERVICES = ["iam", "kms", "lambda", "logs", "sqs"]

_PREFIX = "sim2real-xsvc-"
_MANAGED = {"sim2real": "true", "sim2real:prefix": _PREFIX.rstrip("-")}

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_HANDLER = """
import boto3, os
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    for record in event.get('Records', []):
        sqs.send_message(QueueUrl=os.environ['FORWARD_TO'], MessageBody=record['body'])
    return {'relayed': len(event.get('Records', []))}
"""


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _zip_bytes(source: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _wait_mapping_state(lam, uuid_: str, wanted: str, *, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=uuid_)
        if last["State"] == wanted:
            return last
        time.sleep(3)
    raise AssertionError(f"mapping {uuid_} never reached {wanted!r}; last state {last!r}")


def _past_role_propagation(fn, *, timeout_s: float = 90.0):
    """Call fn(), retried on the exact InvalidParameterValueException IAM role propagation produces."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so one
    delete is not a teardown; raises if it keeps coming back when the budget runs out.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _drain_for_match(sqs, queue_url: str, marker: str, *, timeout_s: float = 150.0) -> bool:
    """Long-poll queue_url until a message body equal to marker arrives; delete every message seen."""
    deadline = time.monotonic() + timeout_s
    found = False
    while time.monotonic() < deadline:
        wait = min(10, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            if json.loads(msg["Body"]).get("marker") == marker:
                found = True
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if found:
            return True
    return False


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A customer managed KMS key named on an event source mapping's FilterCriteria still lets the
    mapping filter records; GetEventSourceMapping decrypts the criteria while ListEventSourceMappings
    redacts it to null, per the documented encrypted-filter-criteria contract."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    source_q = sqs.create_queue(QueueName=_name(ctx, "src-q"), tags=_MANAGED)
    source_url = source_q["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=source_url))
    source_arn = sqs.get_queue_attributes(
        QueueUrl=source_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    relay_q = sqs.create_queue(QueueName=_name(ctx, "relay-q"), tags=_MANAGED)
    relay_url = relay_q["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=relay_url))
    relay_arn = sqs.get_queue_attributes(
        QueueUrl=relay_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "RegionalLambdaServiceMayEncryptAndDecrypt",
                "Effect": "Allow",
                "Principal": {"Service": f"lambda.{ctx.region}.amazonaws.com"},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description=_name(ctx, "filter-key"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED.items()],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    role_name = _name(ctx, "esm-role")
    role_arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="relay-permissions",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                    "Resource": source_arn,
                },
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": relay_arn},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="relay-permissions"))

    fn_name = _name(ctx, "relay-fn")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    _past_role_propagation(lambda: lam.create_function(
        FunctionName=fn_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": _zip_bytes(_HANDLER)},
        Timeout=30,
        Environment={"Variables": {"FORWARD_TO": relay_url}},
        Tags=_MANAGED,
    ))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    filter_criteria = {"Filters": [{"Pattern": json.dumps({"body": {"kind": ["wanted"]}})}]}
    mapping = _past_role_propagation(lambda: lam.create_event_source_mapping(
        EventSourceArn=source_arn,
        FunctionName=fn_name,
        BatchSize=10,
        FilterCriteria=filter_criteria,
        KMSKeyArn=key_arn,
    ))
    mapping_uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=mapping_uuid))
    _wait_mapping_state(lam, mapping_uuid, "Enabled")

    got = lam.get_event_source_mapping(UUID=mapping_uuid)
    assert got.get("KMSKeyArn") == key_arn, (
        f"GetEventSourceMapping must echo the KMS key it encrypts the filter criteria with, "
        f"got {got.get('KMSKeyArn')!r} expected {key_arn!r}"
    )
    assert got.get("FilterCriteria") == filter_criteria, (
        f"GetEventSourceMapping must decrypt the filter criteria for a caller holding kms:Decrypt, "
        f"got {got.get('FilterCriteria')!r} expected {filter_criteria!r}"
    )

    listed = None
    paginator = lam.get_paginator("list_event_source_mappings")
    for page in paginator.paginate(EventSourceArn=source_arn, FunctionName=fn_name):
        for m in page["EventSourceMappings"]:
            if m["UUID"] == mapping_uuid:
                listed = m
    assert listed is not None, f"ListEventSourceMappings never returned mapping {mapping_uuid}"
    assert listed.get("FilterCriteria") is None, (
        f"ListEventSourceMappings must redact an encrypted filter criteria to null, "
        f"got {listed.get('FilterCriteria')!r}"
    )
    assert listed.get("KMSKeyArn") == key_arn, (
        f"ListEventSourceMappings must still echo the KMS key even while redacting the criteria, "
        f"got {listed.get('KMSKeyArn')!r} expected {key_arn!r}"
    )

    wanted_marker = str(uuid.uuid4())
    skipped_marker = str(uuid.uuid4())
    sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"kind": "ignored", "marker": skipped_marker}))
    sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"kind": "wanted", "marker": wanted_marker}))

    delivered = _drain_for_match(sqs, relay_url, wanted_marker)
    assert delivered, (
        "the encrypted filter criteria stopped the mapping from filtering at all: the matching "
        f"record carrying marker {wanted_marker!r} never reached the relay queue"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
