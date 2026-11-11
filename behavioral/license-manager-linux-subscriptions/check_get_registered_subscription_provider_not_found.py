"""get-registered-subscription-provider-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "get-registered-subscription-provider-not-found"
GROUP = "error-semantics"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """GetRegisteredSubscriptionProvider and DeregisterSubscriptionProvider raise ResourceNotFoundException for
    a well-formed but never-registered ARN and ValidationException for a malformed one, each with its exact
    message."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:license-manager-linux-subscriptions:{ctx.region}:{account_id}:"
        "subscription-provider/00000000-0000-0000-0000-000000000000"
    )
    malformed_arn = "not-an-arn-at-all"
    expected_malformed = ("ValidationException", _arn_pattern_message(malformed_arn))

    get = _error(
        lambda: lls.get_registered_subscription_provider(SubscriptionProviderArn=bogus_arn)
    )
    assert get == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {get!r}"

    deregister = _error(
        lambda: lls.deregister_subscription_provider(SubscriptionProviderArn=bogus_arn)
    )
    assert deregister == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {deregister!r}"

    get_malformed = _error(
        lambda: lls.get_registered_subscription_provider(SubscriptionProviderArn=malformed_arn)
    )
    assert get_malformed == expected_malformed, (
        f"expected {expected_malformed!r}, got {get_malformed!r}"
    )

    deregister_malformed = _error(
        lambda: lls.deregister_subscription_provider(SubscriptionProviderArn=malformed_arn)
    )
    assert deregister_malformed == expected_malformed, (
        f"expected {expected_malformed!r}, got {deregister_malformed!r}"
    )


_NOT_FOUND = ("ResourceNotFoundException", "Registered Subscription Provider not found")
_ARN_PATTERN = (
    r"arn:[a-z0-9-\.]{1,63}:[a-z0-9-\.]{1,63}:[a-z0-9-\.]{1,63}:[a-z0-9-\.]{1,63}:"
    r"[a-z0-9-\.]{1,510}/[a-z0-9-\.]{1,510}"
)


def _arn_pattern_message(value: str) -> str:
    return (
        f"1 validation error detected: Value '{value}' at 'subscriptionProviderArn' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_ARN_PATTERN}"
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
    discovery enabled and settled; onboard it (idempotent) if it isn't yet. Real AWS
    runs this as an account-wide async workflow that can outlive a single check's
    body budget on a never-before-onboarded account, and a second UpdateServiceSettings
    issued against a workflow the read path hasn't caught up to yet (an observed
    eventual-consistency gap between the Status field and the workflow lock) is
    rejected with "Customer already has a pending workflow" — which means the same
    thing as Status == InProgress and must be waited out the same way, not raised."""
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

    if settings.get("Status") != "InProgress":
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
                message = error.get("Message", "")
                if "pending workflow" in message.lower():
                    break
                if (
                    error["Code"] != "ValidationException"
                    or message != "Customer does not have service linked role present"
                    or time.monotonic() >= role_deadline
                ):
                    raise
                time.sleep(5.0)

    last = None
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("LinuxSubscriptionsDiscovery") == "Enabled" and last.get("Status") == "Completed":
            return last
        if last.get("Status") != "InProgress":
            time.sleep(5.0)
            continue
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within 900s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
