"""list-protections-requires-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-protections-requires-subscription"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With GetSubscriptionState reporting INACTIVE, ListProtections raises ResourceNotFoundException "The
    subscription does not exist." rather than returning an empty list.
    """
    shield = ctx.client("shield")

    state = shield.get_subscription_state()["SubscriptionState"]
    assert state == "INACTIVE", (
        f"positive control failed: expected an unsubscribed test account (INACTIVE) for the "
        f"ListProtections contract below to apply, got {state!r}"
    )

    error = _client_error(lambda: shield.list_protections())
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    assert error.get("Message") == "The subscription does not exist.", (
        f"expected a subscription-not-found message, got {error!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected ListProtections to raise without a subscription, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
