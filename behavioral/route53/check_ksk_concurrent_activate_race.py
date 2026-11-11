"""ksk-concurrent-activate-race."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ksk-concurrent-activate-race"
GROUP = "concurrency"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent Activate and Deactivate on one KSK serialize: it settles in one status matching
    the call that succeeded, and any collision fails only with ConcurrentModification."""
    r53 = ctx.client("route53")
    zone_id = _create_plain_zone(ctx)
    kms_arn = _create_dnssec_kms_key(ctx)
    name = _ksk_name(ctx, "race")

    r53.create_key_signing_key(
        CallerReference=ctx.unique_name("cr-"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=kms_arn,
        Name=name,
        Status="ACTIVE",
    )
    ctx.on_cleanup(lambda: _best_effort_remove_ksk(ctx, zone_id, name))
    _poll_ksk_status(ctx, zone_id, name, "ACTIVE")

    from botocore.exceptions import ClientError

    # Activate on an ACTIVE KSK is an idempotent success on its own, so whichever racer lands
    # first, the other call is individually legal and only the concurrency guard may refuse it.
    again = r53.activate_key_signing_key(HostedZoneId=zone_id, Name=name)
    assert "ChangeInfo" in again, f"re-activating an ACTIVE KSK must succeed, got {again!r}"
    _poll_ksk_status(ctx, zone_id, name, "ACTIVE")

    results: dict[str, object] = {}
    errors: dict[str, str] = {}

    def _activate():
        return r53.activate_key_signing_key(HostedZoneId=zone_id, Name=name)

    def _deactivate():
        return r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(_activate): "activate", pool.submit(_deactivate): "deactivate"}
        for fut, label in futures.items():
            try:
                results[label] = fut.result()
            except ClientError as err:
                errors[label] = err.response["Error"]["Code"]

    # Every submitted call got SOME outcome -- nothing hung or silently vanished.
    assert len(results) + len(errors) == 2, (
        f"expected 2 outcomes (1 per racer), got results={results!r} errors={errors!r}"
    )

    # Any failure on either racer can only be the concurrency guard, never a
    # KSK-status precondition error (both calls are individually always legal from
    # ACTIVE: Activate is a same-state idempotent no-op, Deactivate is the valid
    # transition) -- so a non-ConcurrentModification error would mean the guard
    # mis-attributed a spurious precondition failure to the race.
    assert set(errors.values()) <= {"ConcurrentModification"}, (
        f"expected only ConcurrentModification errors, got {errors!r}"
    )

    for label, resp in results.items():
        assert "ChangeInfo" in resp, f"{label} response missing ChangeInfo: {resp!r}"

    # Whichever call(s) actually landed, the KSK settles into exactly one terminal
    # status -- racing to completion never leaves it ambiguous/corrupted, and that
    # status must match the call(s) that actually reported success.
    final = _poll_ksk_stable(ctx, zone_id, name)
    assert final in ("ACTIVE", "INACTIVE"), (
        f"expected KSK to settle into ACTIVE or INACTIVE, got {final!r}"
    )
    if "activate" in results and "deactivate" not in results:
        assert final == "ACTIVE", (
            f"only activate landed but final status is {final!r}, expected ACTIVE"
        )
    if "deactivate" in results and "activate" not in results:
        assert final == "INACTIVE", (
            f"only deactivate landed but final status is {final!r}, expected INACTIVE"
        )


def _poll_ksk_stable(ctx, zone_id, name, timeout_s=90.0, interval_s=2.0, stable_reads=2):
    """Poll GetDNSSEC until the KSK reports the same ACTIVE or INACTIVE status across consecutive
    reads (the async change has fully settled), then return that settled status."""
    import time

    r53 = ctx.client("route53")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    streak = 0
    while time.monotonic() < deadline:
        ksks = r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
        match = next((k for k in ksks if k["Name"] == name), None)
        current = match["Status"] if match else "<absent>"
        if current not in ("ACTIVE", "INACTIVE"):
            streak = 0
            last = current
        elif current == last:
            streak += 1
            if streak >= stable_reads:
                return current
        else:
            streak = 1
            last = current
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"KSK {name} status to settle: the run budget ended first; not graded")
    raise AssertionError(f"KSK {name} status never settled (last saw {last})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _best_effort(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
            "NotFoundException",
        ):
            raise


def _ksk_name(ctx, suffix):
    return ctx.unique_name(f"sim2real{suffix}").replace("-", "_")


def _best_effort_remove_ksk(ctx, zone_id, name):
    r53 = ctx.client("route53")
    _best_effort(lambda: r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name))
    _best_effort(lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name))


def _create_plain_zone(ctx):
    r53 = ctx.client("route53")
    zone = r53.create_hosted_zone(
        Name=ctx.unique_name("sim2real-r53-") + ".test.",
        CallerReference=ctx.unique_name("callerref-"),
    )["HostedZone"]
    zone_id = zone["Id"]
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: r53.delete_hosted_zone(Id=zone_id)))
    return zone_id


def _kms_dnssec_policy(account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-dnssec-key-policy",
            "Statement": [
                {
                    "Sid": "EnableRootAccountPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowRoute53DNSSECService",
                    "Effect": "Allow",
                    "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                    "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                    "Resource": "*",
                },
                {
                    "Sid": "AllowRoute53DNSSECCreateGrant",
                    "Effect": "Allow",
                    "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                    "Action": "kms:CreateGrant",
                    "Resource": "*",
                    "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}},
                },
            ],
        }
    )


def _kms_client_for_dnssec(ctx):
    """A KMS client in us-east-1: Route 53 DNSSEC accepts only a customer managed key there,
    whatever region the run targets."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
    kms = _kms_client_for_dnssec(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_kms_dnssec_policy(account_id),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))
    return key["Arn"]


def _poll_ksk_status(ctx, zone_id, name, expected_status, timeout_s=90.0, interval_s=1.0):
    import time

    r53 = ctx.client("route53")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ksks = r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
        match = next((k for k in ksks if k["Name"] == name), None)
        last = match["Status"] if match else "<absent>"
        if last == expected_status:
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"KSK {name} to reach status {expected_status}: the run budget ended first; not graded")
    raise AssertionError(f"KSK {name} never reached status {expected_status} (last saw {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
