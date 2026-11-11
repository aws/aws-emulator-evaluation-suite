"""tag-resource-exceeds-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """RegisterSubscriptionProvider with more than 50 tags raises BadRequestException with its exact message,
    while the same call with valid tags and the same non-genuine token raises the token-validation
    ValidationException; neither registers a provider."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    before = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    before_count = len(before.get("RegisteredSubscriptionProviders", []))

    control_secret_arn = _create_secret(ctx, "fake-redhat-offline-token-taglimit-control")
    control_code, control_message = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat",
            SecretArn=control_secret_arn,
            Tags={"control-key": "control-value"},
        )
    )
    assert (control_code, control_message) == _TOKEN_REJECTED, (
        f"control call (valid-sized Tags, non-genuine token) expected {_TOKEN_REJECTED!r}, "
        f"got {(control_code, control_message)!r}"
    )

    test_secret_arn = _create_secret(ctx, "fake-redhat-offline-token-taglimit-test")
    too_many_tags = {f"key-{i}": f"value-{i}" for i in range(51)}
    over_code, over_message = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat", SecretArn=test_secret_arn, Tags=too_many_tags
        )
    )
    expected_over = (
        "BadRequestException",
        "The resultant tag set must not have more than 50 user tags.",
    )
    assert (over_code, over_message) == expected_over, (
        f"51-tag call expected {expected_over!r} (distinct from the token-validity "
        f"ValidationException), got code={over_code!r} message={over_message!r}"
    )
    assert over_code != control_code, (
        f"51-tag rejection code {over_code!r} matches the token-validity control's code "
        f"{control_code!r} — the tag-count limit is not being distinguished from token "
        f"validation, so this cannot tell an over-limit rejection from a target that "
        f"rejects every RegisterSubscriptionProvider call the same way"
    )

    after = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    after_count = len(after.get("RegisteredSubscriptionProviders", []))
    assert after_count == before_count, (
        f"expected no provider registered after either rejected call, "
        f"before={before_count} after={after_count}"
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
    """Call fn(); return (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    settings = lls.get_service_settings()
    already_in_flight = settings.get("Status") == "InProgress"
    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it.
    while settings.get("Status") == "InProgress" and time.monotonic() < deadline:
        time.sleep(5.0)
        settings = lls.get_service_settings()

    if settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed":
        return settings

    if already_in_flight:
        # It was already in flight before this check ever called
        # UpdateServiceSettings, so a call now would race the in-flight workflow
        # (real AWS answers "Customer already has a pending workflow") instead of
        # starting anything new. Time out cleanly rather than raise that instead.
        raise AssertionError(f"onboarding did not settle within 180s (last={settings!r})")

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
