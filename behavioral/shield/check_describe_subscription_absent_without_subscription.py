"""describe-subscription-absent-without-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-subscription-absent-without-subscription"
GROUP = "state"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With GetSubscriptionState reporting INACTIVE, DescribeSubscription raises ResourceNotFoundException with
    the exact message "The subscription does not exist.".
    """
    shield = ctx.client("shield")

    state = shield.get_subscription_state()["SubscriptionState"]
    assert state == "INACTIVE", (
        f"positive control: expected INACTIVE subscription state on an unsubscribed test "
        f"account, got {state!r}"
    )

    code, message = _error_code(lambda: shield.describe_subscription())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The subscription does not exist.", f"unexpected message {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected describe_subscription to raise ResourceNotFoundException, but it "
        f"succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
