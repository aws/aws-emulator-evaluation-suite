"""register-duplicate-source-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-duplicate-source-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """RegisterSubscriptionProvider rejects a source other than "RedHat" with ValidationException naming the
    enum, while "RedHat" with a non-genuine token is rejected with the token-validation error instead;
    neither call registers a provider."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    before = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    before_count = len(before.get("RegisteredSubscriptionProviders", []))

    invalid = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="Ubuntu",
            SecretArn=(
                f"arn:aws:secretsmanager:{ctx.region}:123456789012:secret:sim2real-fake-abc123"
            ),
        )
    )
    expected_invalid = (
        "ValidationException",
        "1 validation error detected: Value 'Ubuntu' at 'subscriptionProviderSource' failed "
        "to satisfy constraint: Member must satisfy enum value set: [RedHat]",
    )
    assert invalid == expected_invalid, (
        f"expected {expected_invalid!r} for source 'Ubuntu', got {invalid!r}"
    )

    after = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    assert len(after.get("RegisteredSubscriptionProviders", [])) == before_count, (
        f"expected no provider registered after the rejected call, "
        f"before={before_count} after={len(after.get('RegisteredSubscriptionProviders', []))}"
    )

    # Positive control: "RedHat" is the one valid enum value, so it must get PAST the
    # enum-domain check above. We have no genuine Red Hat offline token to complete a
    # real registration, so this leg is still rejected -- but it must be rejected for a
    # *different* reason than the enum check, or this check cannot tell "rejects
    # Ubuntu specifically" from "rejects every RegisterSubscriptionProvider call".
    secret_arn = _create_secret(ctx, "fake-redhat-offline-token-duplicate-source-test")
    valid_source = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat", SecretArn=secret_arn
        )
    )
    assert valid_source == _TOKEN_REJECTED, (
        f"expected {_TOKEN_REJECTED!r} for a fake RedHat token (a token rejection, not the "
        f"enum-constraint one), got {valid_source!r}"
    )

    after_positive = lls.list_registered_subscription_providers(
        SubscriptionProviderSources=["RedHat"]
    )
    assert len(after_positive.get("RegisteredSubscriptionProviders", [])) == before_count, (
        f"expected no provider registered after the fake-token RedHat attempt either, "
        f"before={before_count} after={len(after_positive.get('RegisteredSubscriptionProviders', []))}"
    )


_TOKEN_REJECTED = ("ValidationException", "The subscription provider token is invalid or expired")


def _create_secret(ctx, value: str) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-lls-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=value,
        Tags=[{"Key": "LicenseManagerLinuxSubscriptions", "Value": "enabled"}],
    )
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


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

    deadline = time.monotonic() + 250.0
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
        # A freshly created service-linked role can lag a few seconds before
        # license-manager-linux-subscriptions can see it (IAM propagation); retry
        # UpdateServiceSettings on that specific message within a short bounded window.
        role_deadline = time.monotonic() + 30.0
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
                message = err.response["Error"].get("Message", "").lower()
                if "pending workflow" in message:
                    break
                if "service linked role" in message and time.monotonic() < role_deadline:
                    time.sleep(3.0)
                    continue
                raise

    last = None
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("LinuxSubscriptionsDiscovery") == "Enabled" and last.get("Status") == "Completed":
            return last
        if last.get("Status") != "InProgress":
            time.sleep(5.0)
            continue
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within 250s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
