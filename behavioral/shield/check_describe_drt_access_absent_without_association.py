"""describe-drt-access-absent-without-association."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-drt-access-absent-without-association"
GROUP = "state"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDRTAccess on an account without a Shield Advanced subscription raises ResourceNotFoundException
    with the exact message "The subscription does not exist.", naming the missing subscription.
    """
    shield = ctx.client("shield")
    code, message = _error_code(lambda: shield.describe_drt_access())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} msg={message!r}"
    assert message == "The subscription does not exist.", (
        f"expected the not-found reason to name the missing subscription, got message={message!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
