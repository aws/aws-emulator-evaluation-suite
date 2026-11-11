"""list-registered-subscription-providers-maxresults-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-registered-subscription-providers-maxresults-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """ListRegisteredSubscriptionProviders rejects MaxResults above 100 and below 1 with ValidationException and
    its exact message (sent with client-side validation off), and accepts an in-range value."""
    lls = ctx.client("license-manager-linux-subscriptions")
    unchecked = ctx.client(
        "license-manager-linux-subscriptions", config=Config(parameter_validation=False)
    )
    _ensure_onboarded(ctx, lls)

    high = _error(lambda: unchecked.list_registered_subscription_providers(MaxResults=101))
    expected_high = (
        "ValidationException",
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 100",
    )
    assert high == expected_high, (
        f"expected {expected_high!r} for MaxResults=101 (above the 1-100 range), got {high!r}"
    )

    low = _error(lambda: unchecked.list_registered_subscription_providers(MaxResults=0))
    expected_low = (
        "ValidationException",
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1",
    )
    assert low == expected_low, (
        f"expected {expected_low!r} for MaxResults=0 (below the 1-100 range), got {low!r}"
    )

    # Positive control: the maximum in-range value is accepted, proving the account is
    # otherwise healthy for this call and the rejections above are range-specific.
    ok = lls.list_registered_subscription_providers(MaxResults=100)
    assert "RegisteredSubscriptionProviders" in ok, (
        f"expected RegisteredSubscriptionProviders in response for MaxResults=100, "
        f"got keys {sorted(ok)!r}"
    )
    providers = ok["RegisteredSubscriptionProviders"]
    assert isinstance(providers, list) and len(providers) <= 100, (
        f"expected a list of at most 100 providers for MaxResults=100, got {providers!r}"
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
    discovery enabled and settled; onboard it (idempotent) if it isn't yet.

    Measured against real AWS: a fresh account's onboarding workflow (the
    ``Account-Onboard`` async step behind UpdateServiceSettings) can take upwards of ~195s to
    reach ``Completed``, and a first-time onboarding can take many minutes, so this waits 900s."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900.0
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

    # A service-linked role just created (or already present) can take a few seconds to
    # propagate before UpdateServiceSettings will recognize it -- measured against real AWS,
    # which answered "Customer does not have service linked role present" immediately after
    # a successful CreateServiceLinkedRole call.
    role_deadline = time.monotonic() + 90.0
    while True:
        try:
            lls.update_service_settings(
                LinuxSubscriptionsDiscovery="Enabled",
                LinuxSubscriptionsDiscoverySettings={
                    "OrganizationIntegration": "Disabled",
                    "SourceRegions": [ctx.region],
                },
                AllowUpdate=True,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if (
                code != "ValidationException"
                or "service linked role" not in message.lower()
                or time.monotonic() >= role_deadline
            ):
                raise
            time.sleep(3.0)

    last = None
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            return last
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within 900s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
