"""list-linux-subscriptions-and-instances-basic-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-linux-subscriptions-and-instances-basic-shape"
GROUP = "read-apis"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """ListLinuxSubscriptions and ListLinuxSubscriptionInstances return well-formed
    collections (the sole read path for discovered subscription data)."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    subs = lls.list_linux_subscriptions()
    assert "Subscriptions" in subs, f"ListLinuxSubscriptions response has no 'Subscriptions' key: {subs!r}"
    assert isinstance(subs["Subscriptions"], list), (
        f"'Subscriptions' should be a list, got {type(subs['Subscriptions']).__name__}: {subs['Subscriptions']!r}"
    )
    for item in subs["Subscriptions"]:
        assert "Name" in item, f"subscription item missing 'Name': {item!r}"
        assert "Type" in item, f"subscription item missing 'Type': {item!r}"

    # Freeze detector: discovery is a passive catalog read, so two back-to-back calls with nothing
    # mutated between them must agree exactly. This is the one assertion here that a real target
    # cannot pass by accident — an empty-collection stub still has to be *the same* empty collection
    # twice, and a target that fabricates or races its response will disagree.
    subs_again = lls.list_linux_subscriptions()
    assert subs_again.get("Subscriptions") == subs["Subscriptions"], (
        "two consecutive ListLinuxSubscriptions calls disagree with nothing mutated "
        f"in between: first={subs['Subscriptions']!r} second={subs_again.get('Subscriptions')!r}"
    )

    instances = lls.list_linux_subscription_instances()
    assert "Instances" in instances, f"ListLinuxSubscriptionInstances response has no 'Instances' key: {instances!r}"
    assert isinstance(instances["Instances"], list), (
        f"'Instances' should be a list, got {type(instances['Instances']).__name__}: {instances['Instances']!r}"
    )
    for item in instances["Instances"]:
        assert "InstanceID" in item, f"instance item missing 'InstanceID': {item!r}"

    instances_again = lls.list_linux_subscription_instances()
    assert instances_again.get("Instances") == instances["Instances"], (
        "two consecutive ListLinuxSubscriptionInstances calls disagree with nothing "
        f"mutated in between: first={instances['Instances']!r} second={instances_again.get('Instances')!r}"
    )


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
    import time
    from botocore.exceptions import ClientError

    # A fresh account's first Account-Onboard run has been observed taking
    # well over 180s to reach Completed against real AWS; 270s leaves the
    # list calls that follow a margin inside the 300s check budget.
    deadline = time.monotonic() + 270.0
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
    raise AssertionError(f"onboarding did not settle within 270s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
