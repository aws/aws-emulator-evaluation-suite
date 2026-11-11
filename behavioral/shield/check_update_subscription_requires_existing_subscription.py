"""update-subscription-requires-existing-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-subscription-requires-existing-subscription"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSubscription raises ResourceNotFoundException when there is no active Shield
    Advanced subscription for the account to update AutoRenew on."""
    shield = ctx.client("shield")
    code, message = _error_code(lambda: shield.update_subscription(AutoRenew="DISABLED"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The subscription does not exist.", f"unexpected message {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateSubscription to be rejected with no active subscription, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
