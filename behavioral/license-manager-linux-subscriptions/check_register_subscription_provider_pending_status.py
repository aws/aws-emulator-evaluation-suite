"""register-subscription-provider-pending-status."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-subscription-provider-pending-status"
GROUP = "error-semantics"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """With discovery Enabled and Completed, RegisterSubscriptionProvider with a non-genuine Red Hat token is
    rejected with ValidationException and the exact token-validation message, and registers no provider."""
    lls = ctx.client("license-manager-linux-subscriptions")
    settings = _ensure_onboarded(ctx, lls)
    assert settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed", (
        f"expected Linux subscriptions discovery Enabled/Completed before the token "
        f"test so the account is a valid positive control, got {settings!r}"
    )

    before = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    before_count = len(before.get("RegisteredSubscriptionProviders", []))

    secret_arn = _create_secret(ctx, "fake-redhat-offline-token-pending-test")
    code, message = _error_code(
        ctx,
        lls,
        lambda: lls.register_subscription_provider(
            SubscriptionProviderSource="RedHat", SecretArn=secret_arn
        ),
    )
    assert (code, message) == _TOKEN_REJECTED, (
        f"expected {_TOKEN_REJECTED!r} for a syntactically-valid secret holding a "
        f"non-genuine RedHat token (the token named as the problem, distinct from an "
        f"ARN-pattern or request-shape rejection), got code={code!r} message={message!r}"
    )

    after = lls.list_registered_subscription_providers(SubscriptionProviderSources=["RedHat"])
    after_count = len(after.get("RegisteredSubscriptionProviders", []))
    assert after_count == before_count, (
        f"expected no provider left registered after the rejected call, "
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


def _error_code(ctx, lls, fn):
    try:
        resp = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    arn = resp.get("SubscriptionProviderArn")
    if arn:
        ctx.on_cleanup(lambda: lls.deregister_subscription_provider(SubscriptionProviderArn=arn))
    raise AssertionError(
        f"expected RegisterSubscriptionProvider with a fake RedHat token to be "
        f"rejected, but it succeeded: {resp!r}"
    )


def _ensure_onboarded(ctx, lls):
    """Provider/list/tag operations require the account to have Linux subscriptions
    discovery enabled and settled; onboard it (idempotent) if it isn't yet."""
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

    if settings.get("Status") == "InProgress":
        # The wait above exhausted its budget with a workflow still in flight.
        # UpdateServiceSettings rejects a second call while one is pending
        # ("Customer already has a pending workflow"), so retrying it here would
        # not speed anything up — only an honest timeout is correct.
        raise AssertionError(f"onboarding did not settle within budget (last={settings!r})")

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(
            AWSServiceName="license-manager-linux-subscriptions.amazonaws.com"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidInput":
            raise

    # CreateServiceLinkedRole is not immediately visible to UpdateServiceSettings —
    # a freshly-created (or freshly-confirmed) SLR can still be rejected for a few
    # seconds with "Customer does not have service linked role present".
    slr_deadline = time.monotonic() + 30.0
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
                error["Code"] == "ValidationException"
                and "service linked role" in error.get("Message", "").lower()
                and time.monotonic() < slr_deadline
            ):
                time.sleep(3.0)
                continue
            raise

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
