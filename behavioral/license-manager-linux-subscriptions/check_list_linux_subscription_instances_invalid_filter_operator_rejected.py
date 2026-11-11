"""list-linux-subscription-instances-invalid-filter-operator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-linux-subscription-instances-invalid-filter-operator-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """ListLinuxSubscriptionInstances rejects an unsupported Filter Operator value
    (invalid-enum-combination boundary)."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    code = _error_code(
        lambda: lls.list_linux_subscription_instances(
            Filters=[{"Name": "Region", "Values": [ctx.region], "Operator": "BogusOperator"}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"

    # Positive control: a supported operator is accepted and returns a well-formed response.
    ok = lls.list_linux_subscription_instances(
        Filters=[{"Name": "Region", "Values": [ctx.region], "Operator": "Equal"}]
    )
    assert "Instances" in ok, f"expected 'Instances' key in response, got keys {list(ok)!r}"
    assert isinstance(ok["Instances"], list), (
        f"expected Instances to be a list, got {type(ok['Instances'])!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
    import time
    from botocore.exceptions import ClientError

    budget_s = 240.0
    deadline = time.monotonic() + budget_s
    settings = lls.get_service_settings()
    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it.
    while settings.get("Status") == "InProgress" and time.monotonic() < deadline:
        time.sleep(5.0)
        settings = lls.get_service_settings()

    if settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed":
        return settings

    # Only (re)trigger onboarding if nothing is in flight — calling UpdateServiceSettings
    # while a workflow is already InProgress is rejected with ValidationException
    # ("Customer already has a pending workflow"), so a wait-out that ran to the deadline
    # without seeing InProgress clear must NOT fall through to a fresh update call.
    if settings.get("Status") != "InProgress":
        iam = ctx.client("iam")
        try:
            iam.create_service_linked_role(
                AWSServiceName="license-manager-linux-subscriptions.amazonaws.com"
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInput":
                raise
        lls.update_service_settings(
            LinuxSubscriptionsDiscovery="Enabled",
            LinuxSubscriptionsDiscoverySettings={
                "OrganizationIntegration": "Disabled",
                "SourceRegions": [ctx.region],
            },
            AllowUpdate=True,
        )

    last = settings
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            if last.get("LinuxSubscriptionsDiscovery") == "Enabled" and last.get("Status") == "Completed":
                return last
            raise AssertionError(f"onboarding settled into a non-completed state (last={last!r})")
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within {budget_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
