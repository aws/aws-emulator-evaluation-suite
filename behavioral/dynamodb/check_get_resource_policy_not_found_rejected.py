"""get-resource-policy-not-found-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-policy-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a table without a policy raises PolicyNotFoundException with the exact message; after
    PutResourcePolicy it returns that policy and revision, and after DeleteResourcePolicy the same error again.
    """
    ddb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    table_name = ctx.unique_name("sim2real-respolicy-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    expected_message = f"Resource-based policy not found for the provided ResourceArn: {table_arn}"
    baseline_code, baseline_message = _error_code_or_raise(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    assert baseline_code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {baseline_code}"
    assert baseline_message == expected_message, (
        f"expected message {expected_message!r}, got {baseline_message!r}"
    )

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dynamodb:DescribeTable",
            "Resource": table_arn,
        }],
    })
    put_resp = _retry_past_throttle(lambda: ddb.put_resource_policy(ResourceArn=table_arn, Policy=policy))
    revision = put_resp["RevisionId"]

    attached = _poll_until(
        lambda: _attempt_get(ddb, table_arn),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
        description="policy visible after PutResourcePolicy",
    )
    assert attached["RevisionId"] == revision, attached
    assert "DescribeTable" in attached["Policy"], attached

    _retry_past_throttle(lambda: ddb.delete_resource_policy(ResourceArn=table_arn, ExpectedRevisionId=revision))

    final_code, final_message = _poll_until(
        lambda: _probe_error_code(ddb, table_arn),
        lambda c: c[0] == "PolicyNotFoundException",
        timeout_s=30.0,
        interval_s=2.0,
        description="policy gone after DeleteResourcePolicy",
    )
    assert final_code == "PolicyNotFoundException", final_code
    assert final_message == expected_message, (
        f"expected message {expected_message!r}, got {final_message!r}"
    )


def _error_code_or_raise(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected {fn!r} to raise a ClientError, it returned successfully")


def _probe_error_code(ddb, table_arn):
    try:
        ddb.get_resource_policy(ResourceArn=table_arn)
        return "SUCCESS", None
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")


def _attempt_get(ddb, table_arn):
    try:
        return ddb.get_resource_policy(ResourceArn=table_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] == "PolicyNotFoundException":
            return None
        raise


def _retry_past_throttle(fn, *, timeout_s=60.0, interval_s=5.0):
    # DynamoDB's resource-policy control-plane APIs (Put/DeleteResourcePolicy) enforce a tight
    # per-resource modification-rate limit; issuing them back-to-back on the same table can draw
    # ThrottlingException or a transient ResourceInUseException while the prior mutation settles.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "ResourceInUseException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
