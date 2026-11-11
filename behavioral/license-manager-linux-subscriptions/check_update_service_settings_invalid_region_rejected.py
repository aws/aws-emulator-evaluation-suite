"""update-service-settings-invalid-region-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "update-service-settings-invalid-region-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """UpdateServiceSettings rejects a SourceRegions entry that isn't a real AWS Region
    even on the Enable path (which has no onboarding precondition), and leaves the
    account's settings unchanged (input-domain boundary)."""
    lls = ctx.client("license-manager-linux-subscriptions")
    ctx.on_cleanup(lambda: _set_discovery(ctx, lls, "Enabled", skip_on_contention=True))

    before = lls.get_service_settings()

    rejected = _error(
        lambda: lls.update_service_settings(
            LinuxSubscriptionsDiscovery="Enabled",
            LinuxSubscriptionsDiscoverySettings={
                "SourceRegions": ["not-a-real-region-9999"],
                "OrganizationIntegration": "Disabled",
            },
            AllowUpdate=True,
        )
    )
    expected = ("ValidationException", "Invalid region name/format : not-a-real-region-9999")
    assert rejected == expected, f"expected {expected!r}, got {rejected!r}"

    after = lls.get_service_settings()
    assert after.get("LinuxSubscriptionsDiscovery") == before.get("LinuxSubscriptionsDiscovery"), (
        f"LinuxSubscriptionsDiscovery changed: before={before.get('LinuxSubscriptionsDiscovery')!r} "
        f"after={after.get('LinuxSubscriptionsDiscovery')!r}"
    )
    assert after.get("LinuxSubscriptionsDiscoverySettings") == before.get("LinuxSubscriptionsDiscoverySettings"), (
        f"LinuxSubscriptionsDiscoverySettings changed: before={before.get('LinuxSubscriptionsDiscoverySettings')!r} "
        f"after={after.get('LinuxSubscriptionsDiscoverySettings')!r}"
    )
    assert after.get("Status") == before.get("Status"), (
        f"Status changed: before={before.get('Status')!r} after={after.get('Status')!r}"
    )

    # Positive control: the same request with a real Region is accepted and settles.
    settled = _set_discovery(ctx, lls, "Enabled")
    assert settled["Status"] == "Completed", settled
    assert settled["LinuxSubscriptionsDiscovery"] == "Enabled", settled


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _set_discovery(ctx, lls, discovery: str, *, skip_on_contention: bool = False):
    deadline = time.monotonic() + 210.0
    settings = lls.get_service_settings()
    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it.
    while settings.get("Status") == "InProgress" and time.monotonic() < deadline:
        time.sleep(5.0)
        settings = lls.get_service_settings()
    if settings.get("LinuxSubscriptionsDiscovery") == discovery and settings.get("Status") == "Completed":
        return settings
    if discovery == "Enabled":
        iam = ctx.client("iam")
        try:
            iam.create_service_linked_role(
                AWSServiceName="license-manager-linux-subscriptions.amazonaws.com"
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInput":
                raise

    # A concurrently-running check may be mid-workflow when we try to issue our own
    # UpdateServiceSettings; retry on "pending workflow" collisions instead of failing.
    # A service-linked role just created above can take a few seconds to propagate,
    # during which the service reports it as absent — retry that too, rather than
    # treating IAM's own eventual consistency as a hard failure.
    issued = False
    while time.monotonic() < deadline:
        try:
            lls.update_service_settings(
                LinuxSubscriptionsDiscovery=discovery,
                LinuxSubscriptionsDiscoverySettings={
                    "OrganizationIntegration": "Disabled",
                    "SourceRegions": [ctx.region],
                },
                AllowUpdate=True,
            )
            issued = True
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ValidationException":
                raise
            msg = str(err).lower()
            if "pending workflow" not in msg and "service linked role" not in msg and "service-linked role" not in msg:
                raise
            time.sleep(8.0)
    if not issued:
        if skip_on_contention:
            return lls.get_service_settings()
        raise AssertionError(
            "could not issue UpdateServiceSettings within the contention window — too "
            "many concurrently-running checks were mid-workflow on this account-wide "
            "shared setting"
        )
    last = None
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            return last
        time.sleep(5.0)
    if skip_on_contention:
        return last or lls.get_service_settings()
    raise AssertionError(
        f"UpdateServiceSettings did not settle within the contention window "
        f"(last={last!r}) — likely contention from other concurrently-running checks"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
