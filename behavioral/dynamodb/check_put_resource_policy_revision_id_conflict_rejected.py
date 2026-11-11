"""put-resource-policy-revision-id-conflict-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-revision-id-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with an ExpectedRevisionId another writer has replaced raises PolicyNotFoundException with the
    exact message and keeps that writer's revision, while the same call with the current revision lands.
    """
    ddb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    table_name = ctx.unique_name("sim2real-behav-rpr-")
    create_resp = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    table_arn = create_resp["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )

    def _policy(sid: str, action: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": action,
                        "Resource": table_arn,
                    }
                ],
            }
        )

    # Writer A's initial read: install the first policy revision and remember it as "what A saw".
    # Note: policy Sid values must be alphanumeric only (no hyphens) or DynamoDB rejects the
    # policy document with a ValidationException before revision-checking even comes into play.
    put_a = _put_policy_with_retry(ddb, table_arn, _policy("WriterAInitial", "dynamodb:DescribeTable"))
    stale_revision = put_a["RevisionId"]
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(ddb, table_arn))

    # Writer B concurrently replaces the policy WITHOUT any revision check, moving the resource
    # to a new, current revision that writer A does not know about.
    put_b = _put_policy_with_retry(ddb, table_arn, _policy("WriterBConcurrent", "dynamodb:GetItem"))
    current_revision = put_b["RevisionId"]
    assert current_revision != stale_revision, "PutResourcePolicy did not advance the RevisionId"

    # Writer A now submits its change, still carrying the now-stale revision it originally read.
    code, message = _error_code_and_message(
        lambda: ddb.put_resource_policy(
            ResourceArn=table_arn,
            Policy=_policy("WriterAStaleSubmit", "dynamodb:PutItem"),
            ExpectedRevisionId=stale_revision,
        )
    )
    assert code == "PolicyNotFoundException", (code, message)
    expected = (
        "Resource-based policy not found for the provided ResourceArn: Requested update for "
        f"policy with revision id {stale_revision}, but the policy associated to target table "
        f"{table_name} has revision id {current_revision}."
    )
    assert message == expected, f"unexpected message {message!r}"

    # The concurrent writer's policy (B's) must be UNCHANGED by A's rejected, stale submission.
    fetched = _get_policy_matching_sid(ddb, table_arn, "WriterBConcurrent")
    assert fetched["RevisionId"] == current_revision, (
        f"stale rejected write must leave the policy at B's revision {current_revision!r}, "
        f"found {fetched['RevisionId']!r}"
    )

    # A correctly-targeted PutResourcePolicy (using the CURRENT revision) is accepted.
    put_c = ddb.put_resource_policy(
        ResourceArn=table_arn,
        Policy=_policy("WriterARetry", "dynamodb:PutItem"),
        ExpectedRevisionId=current_revision,
    )
    new_revision = put_c["RevisionId"]
    assert new_revision != current_revision, (
        f"a correctly-targeted PutResourcePolicy must advance the RevisionId past {current_revision!r}, "
        f"got the same value back"
    )

    # Independent terminal read at the destination: GetResourcePolicy, not the mutating
    # PutResourcePolicy's own response, must show the retried write actually landed.
    landed = _get_policy_matching_sid(ddb, table_arn, "WriterARetry")
    assert landed["RevisionId"] == new_revision, (
        f"GetResourcePolicy must reflect the accepted retry's revision {new_revision!r}, "
        f"found {landed['RevisionId']!r}"
    )


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _safe_delete_resource_policy(ddb: Any, table_arn: str) -> None:
    try:
        ddb.delete_resource_policy(ResourceArn=table_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PolicyNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str | None, str]:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        raise
    raise AssertionError("expected the call to be refused, but it succeeded")


def _put_policy_with_retry(
    ddb: Any, table_arn: str, policy: str, *, timeout_s: float = 90, interval_s: float = 5
) -> dict[str, Any]:
    """DynamoDB's resource-policy control-plane surface enforces a tight per-resource request
    rate; back-to-back PutResourcePolicy calls issued against the same, just-created table can
    transiently 429 (ThrottlingException) or report the resource as still settling
    (ResourceInUseException) — retry for a bounded time rather than treating either as a hard
    failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ddb.put_resource_policy(ResourceArn=table_arn, Policy=policy)
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code in ("ThrottlingException", "ResourceInUseException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _get_policy_matching_sid(
    ddb: Any, table_arn: str, expected_sid: str, *, timeout_s: float = 60, interval_s: float = 3
) -> dict[str, Any]:
    """PutResourcePolicy's effect can lag briefly; a GetResourcePolicy issued immediately after
    may still 404 (PolicyNotFoundException) or briefly return the PREVIOUS statement -- poll
    until the expected statement is actually visible."""

    def _attempt() -> dict[str, Any] | None:
        try:
            resp = ddb.get_resource_policy(ResourceArn=table_arn)
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            if code in ("ThrottlingException", "PolicyNotFoundException"):
                return None
            raise
        if json.loads(resp["Policy"])["Statement"][0]["Sid"] == expected_sid:
            return resp
        return None

    result = _poll_until(_attempt, lambda r: r is not None, timeout_s=timeout_s, interval_s=interval_s)
    return result


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
