"""bulk-put-items-client-token-replay-returns-one-operation."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bulk-put-items-client-token-replay-returns-one-operation"
GROUP = "idempotency"
SERVICES = ["dynamodb"]

_MIN_WRITE_UNITS = 1024
_INPUT_PREFIX = "staged/"
_REPORT_PREFIX = "report/"


def _teardown(undo, *gone: str):
    """A cleanup whose failed delete raises; only the codes in ``gone`` mean it is already away."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return run_undo


def _drop_bucket(s3, bucket: str, *, budget_s: float = 120.0) -> None:
    """Empty and delete ``bucket``, including any report the operation writes as it winds down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _drop_table(ddb, table: str, *, budget_s: float = 120.0) -> None:
    """Delete ``table``, waiting out the hold a running bulk operation keeps on it."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _refusal(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _listed(ddb, operation: str) -> list:
    """Every entry of the account's bulk-operation listing, over all pages, naming ``operation``."""
    found = []
    for page in ddb.get_paginator("list_bulk_operations").paginate():
        found.extend(s for s in page["BulkOperationsSummaryList"]
                     if s["BulkOperationArn"] == operation)
    return found


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A bulk put items start replayed with its own client token returns the one operation it
    already made, and reusing that token with a different write rate is refused outright,
    so neither call leaves a second operation behind.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_StartBulkPutItems.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/BulkPutItems.Requesting.html
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bulk-")
    table = ctx.unique_name("sim2real-behav-bulk-")
    token = str(uuid.uuid4())

    placement = {}
    if ctx.region != "us-east-1":
        placement["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **placement)
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))

    staged = f"{_INPUT_PREFIX}items.json"
    s3.put_object(
        Bucket=bucket,
        Key=staged,
        Body=b'{"Item":{"pk":{"S":"p1"},"payload":{"N":"1"}}}\n',
    )

    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _drop_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    start_request = {
        "ClientToken": token,
        "TableName": table,
        "InputS3Configuration": {
            "S3Bucket": bucket,
            "S3KeyPrefix": _INPUT_PREFIX,
            "InputFormat": "DYNAMODB_JSON",
            "InputCompressionType": "NONE",
        },
        "OutputS3Configuration": {
            "S3Bucket": bucket,
            "S3KeyPrefix": _REPORT_PREFIX,
            "OutputType": ["ERROR"],
        },
        "MaxWriteRequestUnits": _MIN_WRITE_UNITS,
        "PerformanceTier": "STANDARD",
    }

    started = ddb.start_bulk_put_items(**start_request)["BulkOperationDescription"]
    operation = started["BulkOperationArn"]
    ctx.on_cleanup(_teardown(
        lambda: ddb.cancel_bulk_operation(BulkOperationArn=operation),
        "ResourceNotFoundException", "ValidationException",
    ))
    prefix = f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:bulk-operation/"
    assert operation.startswith(prefix) and len(operation) > len(prefix), (
        f"the operation handle is not an account-scoped bulk-operation ARN: {operation!r}"
    )
    assert started["ClientToken"] == token, (
        f"the start echoed client token {started['ClientToken']!r}, not the one it was given"
    )

    # Positive control: the identical request, token included, is the documented idempotent replay
    # and must hand back the operation already running rather than a second one.
    replay = ddb.start_bulk_put_items(**start_request)["BulkOperationDescription"]
    assert replay["BulkOperationArn"] == operation, (
        f"a replay of the same token started a different operation: {replay['BulkOperationArn']!r}"
    )

    mismatched = dict(start_request, MaxWriteRequestUnits=_MIN_WRITE_UNITS * 2)
    code, message = _refusal(lambda: ddb.start_bulk_put_items(**mismatched))
    assert code == "IdempotentParameterMismatchException", (
        f"reusing the token with another write rate gave {code!r}: {message!r}"
    )
    assert message == (
        "Specified idempotent token was already used with different request parameters within the "
        "idempotency window"
    ), f"token-mismatch refusal carried an unexpected message {message!r}"

    described = ddb.describe_bulk_operation(BulkOperationArn=operation)["BulkOperationDescription"]
    assert described["ClientToken"] == token, (
        f"an independent read of the operation reports client token {described['ClientToken']!r}"
    )
    named = sorted(d["TableName"] for d in described["TableDetails"])
    assert named == [table], f"the operation reports it writes to {named!r}, not the table it was given"
    assert described["MaxWriteRequestUnits"] == _MIN_WRITE_UNITS, (
        "the refused start changed the running operation's write rate to "
        f"{described['MaxWriteRequestUnits']!r}"
    )

    listed = _listed(ddb, operation)
    assert len(listed) == 1, (
        f"the account's listing holds {len(listed)} entries for this one operation handle"
    )

    cancelled = ddb.cancel_bulk_operation(BulkOperationArn=operation)
    assert cancelled["BulkOperationArn"] == operation, (
        f"the cancel answered for {cancelled['BulkOperationArn']!r}, not the operation it was given"
    )
    assert cancelled["BulkOperationStatus"] in ("CANCELLING", "CANCELLED"), (
        f"cancelling an in-flight operation reported status {cancelled['BulkOperationStatus']!r}"
    )

    after_cancel = _listed(ddb, operation)
    assert len(after_cancel) == 1, (
        f"after the cancel the listing holds {len(after_cancel)} entries for the operation"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
