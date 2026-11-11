"""list-registered-subscription-providers-reflects-registration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-registered-subscription-providers-reflects-registration"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """ListRegisteredSubscriptionProviders rejects a SubscriptionProviderSources value other than "RedHat" with
    ValidationException and its exact message, and returns a list for the "RedHat" filter."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    bad = _error(
        lambda: lls.list_registered_subscription_providers(
            SubscriptionProviderSources=["NotARealProvider"]
        )
    )
    expected_bad = (
        "ValidationException",
        "1 validation error detected: Value '[NotARealProvider]' at "
        "'subscriptionProviderSources' failed to satisfy constraint: Member must satisfy "
        "constraint: [Member must satisfy enum value set: [RedHat]]",
    )
    assert bad == expected_bad, (
        f"expected {expected_bad!r} for an unsupported filter source, got {bad!r}"
    )

    # Positive control: the one supported source value is accepted.
    ok = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    assert "RegisteredSubscriptionProviders" in ok, (
        f"expected RegisteredSubscriptionProviders in response, got keys {sorted(ok)}"
    )
    assert isinstance(ok["RegisteredSubscriptionProviders"], list), (
        f"expected RegisteredSubscriptionProviders to be a list, got "
        f"{type(ok['RegisteredSubscriptionProviders'])!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    settings = lls.get_service_settings()
    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it.
    while settings.get("Status") == "InProgress" and time.monotonic() < deadline:
        time.sleep(5.0)
        settings = lls.get_service_settings()

    if settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed":
        return settings

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
    last = None
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            return last
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within 180s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
