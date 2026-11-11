"""deregister-removes-subscription-provider."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-removes-subscription-provider"
GROUP = "error-semantics"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """DeregisterSubscriptionProvider on a well-formed but never-registered ARN raises the same
    ResourceNotFoundException twice, and GetRegisteredSubscriptionProvider raises it for that ARN afterwards."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:license-manager-linux-subscriptions:{ctx.region}:{account_id}:"
        "subscription-provider/22222222-2222-2222-2222-222222222222"
    )

    # Positive control: the account/credentials are otherwise healthy for this
    # service, so the rejections below cannot be explained by "everything fails".
    healthy = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    assert isinstance(healthy.get("RegisteredSubscriptionProviders"), list), (
        f"expected a well-formed list from a healthy ListRegisteredSubscriptionProviders "
        f"call, got {healthy!r}"
    )

    first = _error(
        lambda: lls.deregister_subscription_provider(SubscriptionProviderArn=bogus_arn)
    )
    assert first == _NOT_FOUND, (
        f"expected {_NOT_FOUND!r} on first deregister of a never-registered ARN, got {first!r}"
    )

    second = _error(
        lambda: lls.deregister_subscription_provider(SubscriptionProviderArn=bogus_arn)
    )
    assert second == _NOT_FOUND, (
        f"expected the identical {_NOT_FOUND!r} on the repeat deregister call "
        f"(idempotent rejection, no side effect), got {second!r}"
    )

    get = _error(
        lambda: lls.get_registered_subscription_provider(SubscriptionProviderArn=bogus_arn)
    )
    assert get == _NOT_FOUND, (
        f"expected GetRegisteredSubscriptionProvider to still not resolve the ARN after "
        f"the deregister attempts with {_NOT_FOUND!r}, got {get!r}"
    )


_NOT_FOUND = ("ResourceNotFoundException", "Registered Subscription Provider not found")


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
    # A service-linked role just created (or already present) takes a while to become
    # visible: UpdateServiceSettings answers "Customer does not have service linked role
    # present" until it is, so only that refusal is retried, within a bound.
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
            error = err.response["Error"]
            if (
                error["Code"] != "ValidationException"
                or error.get("Message") != "Customer does not have service linked role present"
                or time.monotonic() >= role_deadline
            ):
                raise
            time.sleep(5.0)
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
