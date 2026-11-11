"""get-resource-policy-malformed-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-resource-policy-malformed-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _delete_table_when_settled(ddb, table_name, timeout_s=90.0, interval_s=5.0):
    """DeleteTable is refused with ResourceInUseException while a resource-policy update on
    the table is still pending; retry for a bounded time until it settles."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error_code_and_message(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, so an
    emulator that serves a policy for a resource that has none never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected GetResourcePolicy to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy raises PolicyNotFoundException for an existing table without a policy,
    ResourceNotFoundException for a missing table, and ValidationException for a non-ARN string and an IAM ARN,
    each with the exact message; an attached policy reads back.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-grp-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_settled(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRoot",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dynamodb:*",
                "Resource": table_arn,
            }
        ],
    }
    ddb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: ddb.delete_resource_policy(ResourceArn=table_arn))

    # Positive control: a well-formed ARN with an attached policy succeeds.
    # PutResourcePolicy is documented as asynchronous/eventually consistent --
    # an immediate GetResourcePolicy may still see PolicyNotFoundException --
    # so poll rather than asserting on the very first read. Only that specific
    # code is worth retrying; any other error is a real failure and must
    # surface immediately rather than being masked for the full deadline.
    from botocore.exceptions import ClientError

    resp = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            resp = ddb.get_resource_policy(ResourceArn=table_arn)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "PolicyNotFoundException":
                raise
            time.sleep(3.0)
    assert resp is not None, "resource policy never became readable after PutResourcePolicy"
    assert json.loads(resp["Policy"])["Statement"][0]["Sid"] == "AllowRoot"

    # Class 1: the table genuinely exists but carries no resource policy at
    # all -> PolicyNotFoundException (the policy, not the resource, is missing).
    other_table_name = ctx.unique_name("sim2real-behav-grp-nopolicy-")
    ddb.create_table(
        TableName=other_table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=other_table_name))
    ddb.get_waiter("table_exists").wait(TableName=other_table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    other_table_arn = ddb.describe_table(TableName=other_table_name)["Table"]["TableArn"]

    code_no_policy, message_no_policy = _error_code_and_message(
        lambda: ddb.get_resource_policy(ResourceArn=other_table_arn)
    )
    assert code_no_policy == "PolicyNotFoundException", (
        f"expected PolicyNotFoundException for an existing table with no policy, got {code_no_policy!r}"
    )
    expected_no_policy = f"Resource-based policy not found for the provided ResourceArn: {other_table_arn}"
    assert message_no_policy == expected_no_policy, (
        f"expected message {expected_no_policy!r}, got {message_no_policy!r}"
    )

    # Class 2: a well-formed-shaped ARN whose referenced table never existed
    # -> ResourceNotFoundException (the resource itself is missing), a
    # distinct error class from Class 1 even though both are "not found".
    missing_table_name = ctx.unique_name("sim2real-behav-grp-missing-")
    missing_table_arn = table_arn.rsplit("/", 1)[0] + "/" + missing_table_name
    code_missing, message_missing = _error_code_and_message(
        lambda: ddb.get_resource_policy(ResourceArn=missing_table_arn)
    )
    assert code_missing == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent table ARN, got {code_missing!r}"
    )
    expected_missing = f"Requested resource not found: Table: {missing_table_name} not found"
    assert message_missing == expected_missing, (
        f"expected message {expected_missing!r}, got {message_missing!r}"
    )
    assert code_missing != code_no_policy, "the two not-found classes must be distinguishable"

    # A non-ARN string and an ARN of another service are refused up front with a
    # ValidationException whose message names the malformed value.
    iam_arn = f"arn:aws:iam::{account_id}:role/not-a-dynamodb-resource"
    bogus_cases = (
        (
            "not-a-valid-arn",
            "One or more parameter values were invalid: ARNs must start with 'arn:': not-a-valid-arn",
        ),
        (
            iam_arn,
            f"One or more parameter values were invalid: Invalid resource Arn: {iam_arn}",
        ),
    )
    for bogus, expected_bogus in bogus_cases:
        bogus_code, bogus_message = _error_code_and_message(
            lambda b=bogus: ddb.get_resource_policy(ResourceArn=b)
        )
        assert bogus_code == "ValidationException", (
            f"expected ValidationException for malformed ResourceArn {bogus!r}, got {bogus_code!r}"
        )
        assert bogus_message == expected_bogus, (
            f"expected message {expected_bogus!r}, got {bogus_message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

