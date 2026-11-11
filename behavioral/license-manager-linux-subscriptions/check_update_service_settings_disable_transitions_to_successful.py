"""update-service-settings-disable-transitions-to-successful."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-service-settings-disable-transitions-to-successful"
GROUP = "state"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """Disabling Linux subscriptions discovery drives Status InProgress -> Completed,
    observable via subsequent GetServiceSettings calls. Ends with discovery re-enabled
    (best-effort, via cleanup) so it doesn't disturb other checks."""
    lls = ctx.client("license-manager-linux-subscriptions")

    ctx.on_cleanup(
        lambda: _set_discovery(
            ctx, lls, "Enabled", deadline=time.monotonic() + 50.0, skip_on_contention=True
        )
    )

    # A single onboarding/offboarding transition of this account-wide setting can take more
    # than 250 s to settle from cold, so the two
    # transitions below share one run-scoped deadline rather than each getting a fresh fixed
    # window; onboard-then-offboard from cold needs more than 300s.
    run_deadline = time.monotonic() + 1100.0

    # Ensure the account is onboarded (Enabled + settled) first, since disabling
    # requires prior onboarding.
    enabled = _set_discovery(ctx, lls, "Enabled", deadline=run_deadline)
    assert enabled["Status"] == "Completed", enabled
    assert enabled["LinuxSubscriptionsDiscovery"] == "Enabled", (
        f"expected LinuxSubscriptionsDiscovery=Enabled, got {enabled.get('LinuxSubscriptionsDiscovery')!r}"
    )

    disabled = _set_discovery(ctx, lls, "Disabled", deadline=run_deadline)
    assert disabled["Status"] == "Completed", disabled
    assert disabled["LinuxSubscriptionsDiscovery"] == "Disabled", (
        f"expected LinuxSubscriptionsDiscovery=Disabled, got {disabled.get('LinuxSubscriptionsDiscovery')!r}"
    )


def _set_discovery(ctx, lls, discovery: str, *, deadline: float, skip_on_contention: bool = False):
    from botocore.exceptions import ClientError

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
    # A service-linked role just created above is also not immediately consistent —
    # LLS can answer "Customer does not have service linked role present" for a few
    # seconds after CreateServiceLinkedRole returns, so that's retried too.
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
            if "pending workflow" not in msg and "service linked role" not in msg:
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
