"""register-invalid-secret-arn-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "register-invalid-secret-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """RegisterSubscriptionProvider rejects a SecretArn that isn't a Secrets Manager ARN,
    and no provider resource is created (malformed-reference boundary)."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)
    _ensure_no_existing_redhat_provider(ctx)

    rejected = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat", SecretArn="not-a-valid-secret-arn"
        )
    )
    # The ARN-pattern constraint specifically, not just any ValidationException: the
    # message names the field and cites the regex constraint.
    expected_pattern = (
        "ValidationException",
        "1 validation error detected: Value 'not-a-valid-secret-arn' at 'secretArn' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: "
        r"arn:[a-z0-9-\.]{1,63}:secretsmanager:[a-z0-9-\.]{0,63}:[a-z0-9-\.]{0,63}:secret:"
        r"[^/]{1,1023}",
    )
    assert rejected == expected_pattern, f"expected {expected_pattern!r}, got {rejected!r}"

    still_empty = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    assert not still_empty.get("RegisteredSubscriptionProviders"), (
        f"expected no RedHat provider after the rejected call, got {still_empty!r}"
    )

    # Distinct boundary: a syntactically valid Secrets Manager ARN whose secret holds a
    # non-genuine Red Hat token is ALSO rejected with ValidationException, but for a
    # different reason (token validation, not ARN-pattern validation) — RegisterSubscription
    # Provider still leaves no resource behind either way. Confirmed against real AWS: the two
    # messages are textually distinct ("pattern" constraint vs. "token is invalid or expired"),
    # so this check cannot be satisfied by a target that simply rejects every SecretArn.
    secret_arn = _create_secret(ctx, "fake-redhat-offline-token-arn-test")
    token_rejected = _error(
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat", SecretArn=secret_arn
        )
    )
    assert token_rejected == _TOKEN_REJECTED, (
        f"expected the token-validation rejection {_TOKEN_REJECTED!r}, got {token_rejected!r}"
    )

    still_empty_after = lls.list_registered_subscription_providers(
        SubscriptionProviderSources=["RedHat"]
    )
    assert not still_empty_after.get("RegisteredSubscriptionProviders"), (
        f"expected no RedHat provider after the rejected call, got {still_empty_after!r}"
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


def _deregister(ctx, provider_arn: str) -> None:
    lls = ctx.client("license-manager-linux-subscriptions")
    try:
        lls.deregister_subscription_provider(SubscriptionProviderArn=provider_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_no_existing_redhat_provider(ctx) -> None:
    lls = ctx.client("license-manager-linux-subscriptions")
    resp = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    if resp.get("RegisteredSubscriptionProviders"):
        raise AssertionError(
            "a RedHat subscription provider is already registered in this account; "
            "skipping to avoid disrupting an existing registration"
        )


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

    # Still InProgress after the wait budget: onboarding was already under way (this is not
    # "never triggered"), and AWS rejects a second UpdateServiceSettings while one is pending
    # ("Customer already has a pending workflow") — confirmed against real AWS, where a
    # fresh-account onboarding workflow outlived this budget. Time out cleanly instead of
    # re-triggering into that unrelated error.
    if settings.get("Status") == "InProgress":
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
    settle_deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < settle_deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            return last
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within 180s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
