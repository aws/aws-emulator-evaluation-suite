"""update-hosted-zone-features-limits-exceeded-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-hosted-zone-features-limits-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateHostedZoneFeatures rejects a redundant disable on a fresh zone with InvalidInput
    ("already disabled") and a nonexistent zone with NoSuchHostedZone; neither changes the zone.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/accelerated-recovery.html
    """
    route53 = ctx.client("route53")

    zone_id = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.zone-features-test.com",
        CallerReference=str(uuid.uuid4()),
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))

    # A brand-new zone omits AcceleratedRecoveryStatus rather than reporting "DISABLED".
    baseline = _accelerated_recovery_status(route53, zone_id)
    assert baseline is None, f"expected a fresh zone to report no status yet, got {baseline!r}"

    # The zone is implicitly disabled, so EnableAcceleratedRecovery=False is a redundant no-op
    # that Route 53 rejects with InvalidInput.
    real_zone_error = _client_error(
        lambda: route53.update_hosted_zone_features(
            HostedZoneId=zone_id, EnableAcceleratedRecovery=False
        )
    )
    assert real_zone_error.get("Code") == "InvalidInput", (
        f"expected InvalidInput for a redundant disable on a real zone, got {real_zone_error!r}"
    )
    assert (
        real_zone_error.get("Message")
        == "Accelerated recovery is already disabled for this hosted zone"
    ), f"expected the specific already-disabled reason, got {real_zone_error.get('Message')!r}"

    # Effect absent: the rejected redundant-disable must not have mutated the
    # real zone's feature state either.
    after_noop_reject = _accelerated_recovery_status(route53, zone_id)
    assert after_noop_reject == baseline, (
        f"real zone's feature status must stay unchanged ({baseline!r}), got {after_noop_reject!r}"
    )

    # Break exactly one thing: target a hosted zone id that doesn't exist.
    bogus_id = "Z00000000000000000000"
    bogus_zone_error = _client_error(
        lambda: route53.update_hosted_zone_features(
            HostedZoneId=bogus_id, EnableAcceleratedRecovery=True
        )
    )
    assert bogus_zone_error.get("Code") == "NoSuchHostedZone", (
        f"expected NoSuchHostedZone for a nonexistent zone, got {bogus_zone_error!r}"
    )
    assert bogus_zone_error.get("Message") == f"No hosted zone found with ID: {bogus_id}", (
        bogus_zone_error
    )

    # Effect absent: the real zone's feature state must be untouched by the
    # rejected call against the bogus id.
    unaffected = _accelerated_recovery_status(route53, zone_id)
    assert unaffected == baseline, (
        f"real zone's feature status must stay unchanged ({baseline!r}), got {unaffected!r}"
    )

    # EnableAcceleratedRecovery=True is never sent to a real zone: it takes up to several hours
    # and blocks zone deletion until it is disabled again.


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _accelerated_recovery_status(route53, zone_id: str) -> str | None:
    hosted_zone = route53.get_hosted_zone(Id=zone_id)["HostedZone"]
    features = hosted_zone.get("Features") or {}
    return features.get("AcceleratedRecoveryStatus")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
