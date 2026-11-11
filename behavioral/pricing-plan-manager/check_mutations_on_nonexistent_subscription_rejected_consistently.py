"""mutations-on-nonexistent-subscription-rejected-consistently."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mutations-on-nonexistent-subscription-rejected-consistently"
GROUP = "validation"
SERVICES = ["pricing-plan-manager"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every operation that takes a subscription ARN validates it, with the identical code and
    message, before it looks at any other input the operation also carries.
    """
    ppm = ctx.client("pricing-plan-manager")
    fake_id = ctx.unique_name("sim2real-behav-ppm-sub-")
    fake_arn = f"arn:aws:pricingplanmanager::{ctx.account}:subscription/{fake_id}"
    expected_message = f"Invalid subscription ARN: {fake_arn}"
    fake_resource_arns = [f"arn:aws:route53:::hostedzone/{ctx.unique_name('Z')}"]

    attempts = (
        ("GetSubscription", lambda: ppm.get_subscription(arn=fake_arn)),
        (
            "AssociateResourcesToSubscription",
            lambda: ppm.associate_resources_to_subscription(
                arn=fake_arn, resourceArns=fake_resource_arns, ifMatch="1"
            ),
        ),
        (
            "DisassociateResourcesFromSubscription",
            lambda: ppm.disassociate_resources_from_subscription(
                arn=fake_arn, resourceArns=fake_resource_arns, ifMatch="1"
            ),
        ),
        ("CancelSubscription", lambda: ppm.cancel_subscription(arn=fake_arn, ifMatch="1")),
        (
            "CancelSubscriptionChange",
            lambda: ppm.cancel_subscription_change(arn=fake_arn, ifMatch="1"),
        ),
    )
    for name, fn in attempts:
        code, message = _error(fn)
        assert code == "ValidationException", (
            f"{name}: expected ValidationException, got {code}: {message!r}"
        )
        assert message == expected_message, (
            f"{name}: expected {expected_message!r}, got {message!r}"
        )

    found = []
    for page in ppm.get_paginator("list_subscriptions").paginate():
        for summary in page["subscriptionSummaries"]:
            found.append(summary["arn"])
    assert fake_arn not in found, (
        f"the never-created subscription {fake_arn!r} appears in ListSubscriptions"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
