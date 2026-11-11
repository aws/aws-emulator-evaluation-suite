"""disassociate-drt-role-requires-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-drt-role-requires-subscription"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With GetSubscriptionState reporting INACTIVE, DisassociateDRTRole and DescribeDRTAccess both raise
    ResourceNotFoundException "The subscription does not exist.", not InvalidOperationException for a missing
    DRT role.
    """
    shield = ctx.client("shield")
    state = shield.get_subscription_state()["SubscriptionState"]
    assert state == "INACTIVE", f"expected an unsubscribed (INACTIVE) test account, got {state!r}"

    code, message = _error_code(lambda: shield.disassociate_drt_role())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The subscription does not exist.", f"unexpected message {message!r}"

    # Independent read at a different operation: no DRT role/log-bucket configuration exists to
    # have been disassociated in the first place, confirming the rejection above tracks a real
    # absence rather than an unrelated fault.
    access_code, access_message = _error_code(lambda: shield.describe_drt_access())
    assert access_code == "ResourceNotFoundException", (
        f"expected DescribeDRTAccess to also report no DRT configuration, got {access_code!r}"
    )
    assert access_message == "The subscription does not exist.", f"unexpected message {access_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
