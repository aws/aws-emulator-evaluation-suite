"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy attaches a resource policy visible via GetResourcePolicy (with the
    expected statement content and a fresh RevisionId), and DeleteResourcePolicy removes it
    so a subsequent GetResourcePolicy 404s (PolicyNotFoundException)."""
    ddb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-behav-rp-")
    create_resp = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    table_arn = create_resp["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SimparityBehavioralCheck",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dynamodb:DescribeTable",
                "Resource": table_arn,
            }
        ],
    }
    put_resp = ddb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(policy))
    put_revision = put_resp["RevisionId"]

    def _attempt_get_policy() -> dict[str, Any] | None:
        try:
            resp = ddb.get_resource_policy(ResourceArn=table_arn)
        except Exception as exc:  # noqa: BLE001
            # PutResourcePolicy's effect can lag briefly; a GetResourcePolicy issued
            # immediately after may still 404 until it propagates.
            if _error_code_from_exc(exc) == "PolicyNotFoundException":
                return None
            raise
        if json.loads(resp["Policy"])["Statement"][0]["Sid"] == "SimparityBehavioralCheck":
            return resp
        return None

    fetched = _poll_until(
        _attempt_get_policy, lambda resp: resp is not None, timeout_s=60, interval_s=3
    )
    fetched_policy = json.loads(fetched["Policy"])
    fetched_action = fetched_policy["Statement"][0]["Action"]
    assert fetched_action == "dynamodb:DescribeTable", (
        f"expected fetched policy Action 'dynamodb:DescribeTable', got {fetched_action!r}"
    )
    fetched_resource = fetched_policy["Statement"][0]["Resource"]
    assert fetched_resource == table_arn, (
        f"expected fetched policy Resource {table_arn!r}, got {fetched_resource!r}"
    )
    assert fetched["RevisionId"] == put_revision, (
        f"expected GetResourcePolicy RevisionId {put_revision!r} to match "
        f"PutResourcePolicy's, got {fetched['RevisionId']!r}"
    )

    # DynamoDB's resource-policy control-plane APIs (Put/Get/Delete ResourcePolicy) enforce a
    # tight per-resource request-rate limit; the Put + several polling Get calls just made
    # against this same table can exhaust botocore's own 5 built-in retries and still get
    # ThrottlingException on Delete — retry with a longer backoff instead of treating that as a
    # hard failure.
    _delete_resource_policy_with_retry(ddb, table_arn, put_revision)

    def _get_after_delete() -> tuple[str, str | None]:
        try:
            ddb.get_resource_policy(ResourceArn=table_arn)
            return "STILL_PRESENT", None
        except Exception as exc:  # noqa: BLE001
            message = getattr(exc, "response", {}).get("Error", {}).get("Message")
            return _error_code_from_exc(exc) or "UNKNOWN_ERROR", message

    final_state, final_message = _poll_until(
        _get_after_delete,
        lambda state: state[0] == "PolicyNotFoundException",
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "PolicyNotFoundException", (
        f"expected GetResourcePolicy to report PolicyNotFoundException after "
        f"DeleteResourcePolicy, got {final_state!r}"
    )
    expected = f"Resource-based policy not found for the provided ResourceArn: {table_arn}"
    assert final_message == expected, f"GetResourcePolicy message {final_message!r}, expected {expected!r}"


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _delete_resource_policy_with_retry(
    ddb: Any, table_arn: str, revision: str, *, timeout_s: float = 120, interval_s: float = 10
) -> None:
    # DynamoDB briefly reports the table "still in use" (ResourceInUseException) immediately
    # after the PutResourcePolicy + polling GetResourcePolicy calls just issued against it, while
    # that mutation's own in-flight lock on the resource settles — retry, same as the
    # already-handled ThrottlingException, instead of treating that as a hard failure.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_resource_policy(ResourceArn=table_arn, ExpectedRevisionId=revision)
            return
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code in ("ThrottlingException", "ResourceInUseException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise



def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
