"""get-ec2-instance-recommendations-schema-and-account-scoping."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ec2-instance-recommendations-schema-and-account-scoping"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetEC2InstanceRecommendations unfiltered returns at most maxResults entries, all of the caller's
    account with documented findings, and an instanceArns filter for another account's instance fails
    with InvalidParameterValueException and the exact account-scoping message."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    cross_account_arn = f"arn:aws:ec2:{ctx.region}:111122223333:instance/i-0ffffffffffffffff"
    code, message = _error_code(
        lambda: co.get_ec2_instance_recommendations(instanceArns=[cross_account_arn])
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    assert message == "Invalid permission to access another account. If this is an organization account, request the management account to enable service access.", f"unexpected cross-account message: {message!r}"

    resp = co.get_ec2_instance_recommendations(maxResults=25)
    recommendations = resp["instanceRecommendations"]
    errors = resp["errors"]
    assert len(recommendations) <= 25, f"maxResults=25 not honored: got {len(recommendations)} recommendations"

    valid_findings = {"Underprovisioned", "Overprovisioned", "Optimized", "NotOptimized"}
    for rec in recommendations:
        assert rec["accountId"] == account_id, (
            f"cross-tenant leakage: recommendation for account {rec.get('accountId')!r}, expected {account_id!r}"
        )
        assert rec["finding"] in valid_findings, f"undocumented finding value: {rec.get('finding')!r}"
        expected_arn_prefix = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/"
        assert rec["instanceArn"].startswith(expected_arn_prefix), (
            f"instanceArn {rec['instanceArn']!r} does not start with {expected_arn_prefix!r}"
        )

    # GetRecommendationError (identifier/code/message) per the Smithy model -- documented shape,
    # not exercised by this account's own state, but must hold whenever the target populates it.
    for err in errors:
        assert isinstance(err.get("identifier"), (str, type(None))), f"errors[].identifier not a string: {err!r}"
        assert isinstance(err.get("code"), (str, type(None))), f"errors[].code not a string: {err!r}"
        assert isinstance(err.get("message"), (str, type(None))), f"errors[].message not a string: {err!r}"


def _error_code(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Opt the account in as a precondition, and leave it opted in.

    Enrollment is deliberately not restored: after an opt-out AWS refuses an opt-in for 24
    hours ("Cannot opt-in within 24 hours of opt-out"), so a restore would fail every later
    check in the account for a day.
    """
    status = co.get_enrollment_status()["status"]
    if status == "Active":
        return
    co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
