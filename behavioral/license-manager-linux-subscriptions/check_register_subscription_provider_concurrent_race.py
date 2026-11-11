"""register-subscription-provider-concurrent-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-subscription-provider-concurrent-race"
GROUP = "concurrency"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """Concurrent RegisterSubscriptionProvider calls for RedHat, each with a non-genuine token secret,
    are all rejected with ValidationException, and no provider is left registered afterward."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)
    before = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    # Positive control: the account/credentials are otherwise healthy for this
    # service, so the uniform rejection below cannot be explained by "every
    # RegisterSubscriptionProvider call fails regardless of input".
    assert isinstance(before.get("RegisteredSubscriptionProviders"), list), (
        f"expected a well-formed list from a healthy ListRegisteredSubscriptionProviders "
        f"call, got {before!r}"
    )
    before_count = len(before["RegisteredSubscriptionProviders"])

    secret_arns = [_create_secret(ctx, f"fake-redhat-offline-token-race-{i}") for i in range(4)]

    def _attempt(secret_arn):
        try:
            resp = lls.register_subscription_provider(
                SubscriptionProviderSource="RedHat", SecretArn=secret_arn
            )
            return ("ok", resp["SubscriptionProviderArn"])
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=len(secret_arns)) as pool:
        futures = [pool.submit(_attempt, s) for s in secret_arns]
        results = [f.result() for f in as_completed(futures)]

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]

    assert len(winners) == 0, f"expected zero winners (fake tokens), got {winners}"
    assert len(losers) == len(secret_arns), (
        f"expected all {len(secret_arns)} concurrent registrations to fail, got "
        f"{len(winners)} succeed and {len(losers)} fail: {results}"
    )
    assert all(code == "ValidationException" for _, code in losers), (
        f"expected every concurrent registration to fail with ValidationException, got {losers}"
    )

    after = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    after_count = len(after.get("RegisteredSubscriptionProviders", []))
    assert after_count == before_count, (
        f"expected no provider left registered after the concurrent race, "
        f"before={before_count} after={after_count}"
    )


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


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
    import time
    from botocore.exceptions import ClientError

    # Account onboarding can stay InProgress for several minutes.
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
    # A just-created service-linked role is not visible to the service at once; retry on that refusal.
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
            if (error["Code"], error.get("Message")) != (
                "ValidationException", "Customer does not have service linked role present"
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
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
