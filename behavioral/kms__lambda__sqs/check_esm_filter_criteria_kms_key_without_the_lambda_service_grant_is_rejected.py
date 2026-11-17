"""esm-filter-criteria-kms-key-without-the-lambda-service-grant-is-rejected."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-filter-criteria-kms-key-without-the-lambda-service-grant-is-rejected"
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
def lambda_handler(event, context):
    return {'seen': len(event.get('Records', []))}
"""


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _zip_bytes(source: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


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


def _delete_mapping_past_creating(lam, uuid_: str, *, timeout_s: float = 120.0) -> None:
    """DeleteEventSourceMapping, retried while the mapping is still leaving its transitional state."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ResourceNotFoundException":
                return
            if err.get("Code") != "ResourceInUseException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    # Lambda deletes the mapping in the background, still using its filter criteria key.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.get_event_source_mapping(UUID=uuid_)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise TimeoutError(f"mapping {uuid_} still exists {timeout_s:g} s after its delete")
        time.sleep(3)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises itself if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, call succeeded instead: {result!r}")


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A KMS key whose policy grants no regional Lambda service principal the right to decrypt
    cannot encrypt an event source mapping's filter criteria; the identical mapping succeeds once
    the key policy carries that grant."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    source_q = sqs.create_queue(QueueName=_name(ctx, "src-q"))
    source_url = source_q["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=source_url))
    source_arn = sqs.get_queue_attributes(
        QueueUrl=source_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

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
        PolicyName="receive-from-source",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="receive-from-source"))

    fn_name = _name(ctx, "noop-fn")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
    _past_role_propagation(lambda: lam.create_function(
        FunctionName=fn_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="index.lambda_handler",
        Code={"ZipFile": _zip_bytes(_HANDLER)},
        Timeout=30,
        Tags=_MANAGED,
    ))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    ungranted_key = kms.create_key(
        Description=_name(ctx, "ungranted-key"),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED.items()],
    )["KeyMetadata"]
    ungranted_arn = ungranted_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=ungranted_arn, PendingWindowInDays=7))

    filter_criteria = {"Filters": [{"Pattern": json.dumps({"body": {"kind": ["wanted"]}})}]}
    code, message = _error(lambda: lam.create_event_source_mapping(
        EventSourceArn=source_arn,
        FunctionName=fn_name,
        FilterCriteria=filter_criteria,
        KMSKeyArn=ungranted_arn,
    ))
    assert code == "InvalidParameterValueException", (
        f"a key whose policy never names the regional Lambda service principal must be refused "
        f"as an invalid parameter, got {code!r}: {message!r}"
    )
    assert message == (
        "Lambda service principal was denied access to decrypt your filter criteria. "
        "Please check your KMS key policy"
    ), f"unexpected message for the ungranted key: {message!r}"

    granted_key_policy = {
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
    granted_key = kms.create_key(
        Description=_name(ctx, "granted-key"),
        Policy=json.dumps(granted_key_policy),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED.items()],
    )["KeyMetadata"]
    granted_arn = granted_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=granted_arn, PendingWindowInDays=7))

    mapping = lam.create_event_source_mapping(
        EventSourceArn=source_arn,
        FunctionName=fn_name,
        FilterCriteria=filter_criteria,
        KMSKeyArn=granted_arn,
    )
    mapping_uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: _delete_mapping_past_creating(lam, mapping_uuid))
    assert mapping.get("KMSKeyArn") == granted_arn, (
        f"the identical mapping with a correctly granted key must be accepted and echo it back, "
        f"got {mapping.get('KMSKeyArn')!r} expected {granted_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
