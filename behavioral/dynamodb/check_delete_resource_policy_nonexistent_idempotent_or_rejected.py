"""delete-resource-policy-nonexistent-idempotent-or-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-nonexistent-idempotent-or-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a table without a policy succeeds as a no-op, while with an ExpectedRevisionId it
    raises PolicyNotFoundException with the exact message; with an attached policy's real revision it removes it.
    """
    ddb = ctx.client("dynamodb")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    table_name = ctx.unique_name("sim2real-delrespolicy-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # No policy has ever been attached to this table. Right after CreateTable, the
    # separately-provisioned resource-policy control plane can still be catching up, which
    # surfaces as a transient ResourceNotFoundException rather than the real "no policy attached"
    # outcome -- ride that out rather than treating it as the answer.
    bare_delete = _poll_past_transient(
        lambda: _with_throttle_retry(lambda: ddb.delete_resource_policy(ResourceArn=table_arn))
    )
    assert bare_delete.get("RevisionId", "") == "", bare_delete

    # Independent read, through a different operation than the one that just ran: the no-op must
    # not have side-effected a policy into existence.
    after_bare_delete, after_bare_msg = _error(
        lambda: _with_throttle_retry(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    )
    assert after_bare_delete == "PolicyNotFoundException", (
        f"expected no policy to exist after the no-op delete, got {after_bare_delete!r}"
    )
    expected_get = f"Resource-based policy not found for the provided ResourceArn: {table_arn}"
    assert after_bare_msg == expected_get, (
        f"expected message {expected_get!r}, got {after_bare_msg!r}"
    )

    # With an ExpectedRevisionId supplied, absence of a matching policy becomes an error.
    code, message = _error(
        lambda: _with_throttle_retry(
            lambda: ddb.delete_resource_policy(
                ResourceArn=table_arn, ExpectedRevisionId="nonexistent-revision-id"
            )
        )
    )
    assert code == "PolicyNotFoundException", f"expected PolicyNotFoundException, got {code}"
    expected_msg = (
        "Resource-based policy not found for the provided ResourceArn: Requested update for "
        f"policy with revision id nonexistent-revision-id, but table {table_name} has no "
        "associated policy."
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # Positive control: attach a real policy and prove the identical shape of call -- Delete with
    # an ExpectedRevisionId -- succeeds and genuinely removes it once the revision actually matches.
    # Without this, "rejects a bogus ExpectedRevisionId" is indistinguishable from "rejects every
    # DeleteResourcePolicy that carries an ExpectedRevisionId at all".
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "dynamodb:DescribeTable",
                    "Resource": table_arn,
                }
            ],
        }
    )
    put_resp = _with_throttle_retry(
        lambda: ddb.put_resource_policy(ResourceArn=table_arn, Policy=policy_doc)
    )
    real_revision = put_resp["RevisionId"]
    _poll_until(
        lambda: _policy_state(ddb, table_arn),
        lambda state: state == "ATTACHED",
        timeout_s=60,
        interval_s=5,
    )

    _with_throttle_retry(
        lambda: ddb.delete_resource_policy(ResourceArn=table_arn, ExpectedRevisionId=real_revision)
    )

    # Independent read again: the matching-revision delete must have actually removed the policy,
    # not merely returned success while leaving it in place. GetResourcePolicy is eventually
    # consistent with a preceding Delete just as it is with a preceding Put, so poll rather than
    # trusting a single immediate read.
    _poll_until(
        lambda: _policy_state(ddb, table_arn),
        lambda state: state == "ABSENT",
        timeout_s=60,
        interval_s=5,
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An accepted call raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _policy_state(ddb, table_arn):
    """'ATTACHED' when GetResourcePolicy returns a policy, 'ABSENT' on PolicyNotFoundException;
    any other error propagates."""
    try:
        _with_throttle_retry(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    except ClientError as err:
        if err.response["Error"]["Code"] != "PolicyNotFoundException":
            raise
        return "ABSENT"
    return "ATTACHED"


def _with_throttle_retry(fn, *, timeout_s=120.0, interval_s=8.0):
    # DynamoDB's resource-policy mutating/reading APIs (Put/Get/DeleteResourcePolicy) enforce a
    # very low per-resource request rate; back-to-back calls in this check can trip
    # ThrottlingException well within botocore's own client-side retry budget. Ride out a longer
    # horizon instead of treating the throttle itself as the behavior under test.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ThrottlingException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"still throttled after {timeout_s}s: {last_err}")


def _poll_past_transient(fn, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


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
