"""tag-resource-list-untag-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-round-trip"
GROUP = "error-semantics"
SERVICES = ["license-manager-linux-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:license-manager-linux-subscriptions-settings")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource each reject a well-formed but never-registered
    subscription-provider ARN with NotFoundException and its exact message."""
    lls = ctx.client("license-manager-linux-subscriptions")
    _ensure_onboarded(ctx, lls)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:license-manager-linux-subscriptions:{ctx.region}:{account_id}:"
        "subscription-provider/33333333-3333-3333-3333-333333333333"
    )

    tag = _error(lambda: lls.tag_resource(resourceArn=bogus_arn, tags={"Environment": "test"}))
    assert tag == _NOT_FOUND, (
        f"TagResource on a never-registered subscription-provider ARN: expected "
        f"{_NOT_FOUND!r}, got {tag!r}"
    )

    list_tags = _error(lambda: lls.list_tags_for_resource(resourceArn=bogus_arn))
    assert list_tags == _NOT_FOUND, (
        f"ListTagsForResource on a never-registered subscription-provider ARN: expected "
        f"{_NOT_FOUND!r}, got {list_tags!r}"
    )

    untag = _error(lambda: lls.untag_resource(resourceArn=bogus_arn, tagKeys=["Environment"]))
    assert untag == _NOT_FOUND, (
        f"UntagResource on a never-registered subscription-provider ARN: expected "
        f"{_NOT_FOUND!r}, got {untag!r}"
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

    deadline = time.monotonic() + 900.0
    settings = lls.get_service_settings()
    # Another check's onboarding workflow may already be in flight; wait it out
    # instead of racing a second UpdateServiceSettings call against it.
    while settings.get("Status") == "InProgress" and time.monotonic() < deadline:
        time.sleep(5.0)
        settings = lls.get_service_settings()

    if settings.get("LinuxSubscriptionsDiscovery") == "Enabled" and settings.get("Status") == "Completed":
        return settings

    if settings.get("Status") == "InProgress":
        # The wait above exhausted the deadline without the in-flight workflow settling.
        # UpdateServiceSettings itself rejects a second call while one is pending
        # ("Customer already has a pending workflow"), so there is nothing to do but
        # report the timeout rather than race it.
        raise AssertionError(
            f"onboarding workflow still InProgress after 900s, refusing to race a "
            f"second UpdateServiceSettings call against it (last={settings!r})"
        )

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(
            AWSServiceName="license-manager-linux-subscriptions.amazonaws.com"
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidInput":
            raise

    # A freshly-created service-linked role is not always immediately visible to
    # UpdateServiceSettings (IAM propagation lag) — real AWS answers "Customer does
    # not have service linked role present" for a few seconds after creation.
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
            if code != "ValidationException" or "service linked role" not in message.lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "service-linked role never became visible to UpdateServiceSettings "
                    f"within the onboarding deadline (last={err!r})"
                ) from err
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
