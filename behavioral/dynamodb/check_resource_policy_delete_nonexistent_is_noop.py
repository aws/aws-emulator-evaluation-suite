"""resource-policy-delete-nonexistent-is-noop."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-delete-nonexistent-is-noop"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a table without a policy succeeds and GetResourcePolicy still raises
    PolicyNotFoundException with the exact message; with a policy attached, the same delete returns its RevisionId
    and removes it.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-respol-neg-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))
    _wait_table_active(ddb, table_name)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    # Right after a table becomes ACTIVE, the (separately-provisioned)
    # resource-policy control plane can still be catching up with the new
    # table, which surfaces as a transient ResourceNotFoundException instead
    # of the real "no policy attached" outcome. Poll past that transient
    # state before asserting the actual (successful, no-op) delete. Real AWS
    # also enforces a very low request rate on the resource-policy mutating
    # APIs (PutResourcePolicy/DeleteResourcePolicy) -- calling them in a tight
    # poll loop exhausts botocore's own retry budget and surfaces as
    # ThrottlingException, so route every call for this policy through a
    # longer-horizon retry that treats throttling as transient too.
    def _noop_delete_outcome() -> str:
        try:
            _call_with_throttle_retry(lambda: ddb.delete_resource_policy(ResourceArn=table_arn))
        except ClientError as err:
            return err.response["Error"]["Code"]
        return "succeeded"

    outcome = _poll_until(
        _noop_delete_outcome,
        lambda c: c != "ResourceNotFoundException",
        timeout_s=60,
        interval_s=5,
    )
    assert outcome == "succeeded", (
        f"expected DeleteResourcePolicy on a policy-less table to succeed as a no-op, got {outcome!r}"
    )

    # Confirm the no-op truly created no policy: GetResourcePolicy still 404s.
    not_found_message = f"Resource-based policy not found for the provided ResourceArn: {table_arn}"
    after_code, after_message = _error(
        lambda: _call_with_throttle_retry(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    )
    assert after_code == "PolicyNotFoundException", (
        f"expected no policy to exist after the no-op delete, got {after_code!r}"
    )
    assert after_message == not_found_message, f"unexpected message {after_message!r}"

    # Positive control: attach a policy for real, then the identical delete call succeeds.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{table_arn.split(':')[4]}:root"},
                "Action": "dynamodb:DescribeTable",
                "Resource": table_arn,
            }
        ],
    }
    _call_with_throttle_retry(lambda: ddb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(policy_doc)))
    _poll_until(
        lambda: _has_policy(ddb, table_arn),
        lambda v: v is True,
        timeout_s=60,
        interval_s=5,
    )
    delete_resp = _call_with_throttle_retry(lambda: ddb.delete_resource_policy(ResourceArn=table_arn))
    assert delete_resp["RevisionId"], f"expected a real delete to report the removed policy's RevisionId, got {delete_resp!r}"

    # Independent terminal read, at the destination: the real delete must have actually
    # removed the policy, not just returned a success response. Confirmed via GetResourcePolicy
    # -- a different operation than the one that mutated -- rather than trusting delete_resp alone.
    _poll_until(
        lambda: _has_policy(ddb, table_arn),
        lambda v: v is False,
        timeout_s=60,
        interval_s=5,
    )
    final_after_code, final_after_message = _error(
        lambda: _call_with_throttle_retry(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    )
    assert final_after_code == "PolicyNotFoundException", (
        f"expected GetResourcePolicy to 404 after the real delete removed the policy, got {final_after_code!r}"
    )
    assert final_after_message == not_found_message, f"unexpected message {final_after_message!r}"


def _has_policy(ddb, resource_arn: str) -> bool:
    try:
        _call_with_throttle_retry(lambda: ddb.get_resource_policy(ResourceArn=resource_arn))
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] == "PolicyNotFoundException":
            return False
        raise


def _call_with_throttle_retry(fn: Callable[[], Any], *, timeout_s: float = 120, interval_s: float = 8) -> Any:
    # DynamoDB's resource-based-policy mutating/reading APIs
    # (Put/Get/DeleteResourcePolicy) enforce a very low per-resource request
    # rate on real AWS; botocore's own client-side retries exhaust quickly
    # under that limit and surface as ThrottlingException. Retry across a
    # longer horizon with a wider interval instead of failing on the first
    # throttle.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ThrottlingException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"still throttled after {timeout_s}s: {last_err}")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Return (code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
