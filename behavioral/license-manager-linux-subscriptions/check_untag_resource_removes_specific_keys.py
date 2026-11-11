"""untag-resource-removes-specific-keys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-specific-keys"
GROUP = "overly-permissive"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """UntagResource rejects an ARN with the wrong resource-type segment with BadRequestException and a
    well-formed but nonexistent ARN with NotFoundException, each with its exact message: format is checked
    before existence."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    malformed_arn = "not-an-arn-at-all"
    malformed = _error(lambda: lls.untag_resource(resourceArn=malformed_arn, tagKeys=["a", "b"]))
    expected_malformed = ("BadRequestException", "Invalid input resource arn: bad syntax")
    assert malformed == expected_malformed, (
        f"expected {expected_malformed!r} for a malformed ARN, got {malformed!r}"
    )

    well_formed_missing_arn = (
        f"arn:aws:license-manager-linux-subscriptions:{ctx.region}:{account_id}:"
        "subscription-provider/55555555-5555-5555-5555-555555555555"
    )
    not_found = _error(
        lambda: lls.untag_resource(resourceArn=well_formed_missing_arn, tagKeys=["a", "b"])
    )
    assert not_found == _NOT_FOUND, (
        f"expected {_NOT_FOUND!r} for a well-formed but nonexistent ARN, got {not_found!r}"
    )


_NOT_FOUND = ("NotFoundException", "Resource was not found")


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

    budget_s = 250.0
    deadline = time.monotonic() + budget_s
    settings = lls.get_service_settings()

    if settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed":
        return settings

    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it. Only trigger
    # a fresh UpdateServiceSettings if there is no workflow in flight at all — calling
    # it while one is InProgress fails with ValidationException("already has a
    # pending workflow").
    if settings.get("Status") != "InProgress":
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

    last = settings
    while time.monotonic() < deadline:
        last = lls.get_service_settings()
        if last.get("Status") != "InProgress":
            return last
        time.sleep(5.0)
    raise AssertionError(f"onboarding did not settle within {budget_s:.0f}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
