"""get-ebs-volume-recommendations-schema."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ebs-volume-recommendations-schema"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetEBSVolumeRecommendations accepts a new same-account volume ARN without an error for it, fails a
    malformed and a cross-account ARN with InvalidParameterValueException and exact messages, and
    unfiltered returns only the caller's volumes."""
    co = ctx.client("compute-optimizer")
    ec2 = ctx.client("ec2")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    az = _first_available_az(ec2)
    name = ctx.unique_name("sim2real-behav-ebsvol-")
    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=90,
    )
    volume_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:volume/{volume_id}"

    # Positive control: a well-formed, real, same-account volume ARN is accepted. Real
    # AWS has no recommendation yet for a volume created seconds ago (it silently omits
    # it from both arrays rather than erroring), so the control only proves "not rejected".
    positive = co.get_ebs_volume_recommendations(volumeArns=[volume_arn])
    positive_recs = positive.get("volumeRecommendations", [])
    assert isinstance(positive_recs, list), f"expected a list, got {positive_recs!r}"
    positive_errors = positive.get("errors", [])
    assert isinstance(positive_errors, list), f"expected a list, got {positive_errors!r}"
    assert not any(e.get("identifier") == volume_arn for e in positive_errors), (
        f"a real, well-formed, same-account volume ARN was rejected: {positive_errors!r}"
    )

    # Negative (always-invalid input, no restore leg): a malformed ARN can never become
    # valid. Real AWS rejects it deterministically rather than treating it like an
    # unrecognized-but-well-formed identifier (which is silently empty, per the control above).
    code, message = _error_code(lambda: co.get_ebs_volume_recommendations(volumeArns=["not-an-arn"]))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    assert message == "Invalid volume ARN.", f"unexpected malformed-ARN message: {message!r}"

    # Negative: a well-formed ARN for a *different* account's volume is rejected with a
    # distinct, account-scoping-specific message, separating "malformed" from "not yours".
    cross_account_arn = f"arn:aws:ec2:{ctx.region}:111122223333:volume/vol-ffffffffffffffff0"
    code2, message2 = _error_code(
        lambda: co.get_ebs_volume_recommendations(volumeArns=[cross_account_arn])
    )
    assert code2 == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code2}"
    assert message2 == "Invalid permission to access another account. If this is an organization account, request the management account to enable service access.", f"unexpected cross-account message: {message2!r}"

    resp_all = co.get_ebs_volume_recommendations(maxResults=25)
    all_recs = resp_all.get("volumeRecommendations", [])
    assert isinstance(all_recs, list), f"expected a list, got {all_recs!r}"
    all_errors = resp_all.get("errors", [])
    assert isinstance(all_errors, list), f"expected a list, got {all_errors!r}"
    for rec in all_recs:
        assert rec["accountId"] == account_id, f"cross-tenant leak: accountId {rec['accountId']} != {account_id}"
        assert rec["finding"] in ("Optimized", "NotOptimized"), f"unexpected finding {rec['finding']!r}"
        assert rec["volumeArn"].startswith(f"arn:aws:ec2:{ctx.region}:{account_id}:volume/"), (
            f"unexpected volumeArn shape {rec['volumeArn']!r}"
        )


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


def _first_available_az(ec2) -> str:
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert azs, "no available AZs found"
    return azs[0]["ZoneName"]


def _delete_volume(ec2, volume_id: str) -> None:
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state in ("available", "error"),
        timeout_s=90,
    )
    ec2.delete_volume(VolumeId=volume_id)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
