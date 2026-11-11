"""put-account-configuration-out-of-range-days-fails."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-configuration-out-of-range-days-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:acm-account-configuration")
def run(ctx) -> None:
    """PutAccountConfiguration rejects DaysBeforeExpiry outside 1..45 without changing the setting;
    an in-range control write proves the call is otherwise accepted."""
    acm = ctx.client("acm")
    original = _retry_throttle(lambda: acm.get_account_configuration())["ExpiryEvents"]["DaysBeforeExpiry"]

    control_value = 30 if original != 30 else 21
    # IdempotencyToken must match \w+, so a bare hex token is used.
    _retry_throttle(
        lambda: acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": control_value},
            IdempotencyToken=uuid.uuid4().hex[:24],
        )
    )
    # Account-global setting: restore the original value.
    ctx.on_cleanup(
        lambda: acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": original},
            IdempotencyToken=uuid.uuid4().hex[:24],
        )
    )

    reflected = _retry_throttle(lambda: acm.get_account_configuration())["ExpiryEvents"]["DaysBeforeExpiry"]
    assert reflected == control_value, f"positive control: expected {control_value}, got {reflected}"

    try:
        result = acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": 500},
            IdempotencyToken=uuid.uuid4().hex[:24],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"DaysBeforeExpiry=500 must be rejected, but the call succeeded: {result!r}")
    assert code == "ValidationException", code
    assert message == "Days before expiry cannot be over 45.", message

    after = _retry_throttle(lambda: acm.get_account_configuration())["ExpiryEvents"]["DaysBeforeExpiry"]
    assert after == control_value, (
        f"rejected PutAccountConfiguration must not mutate account config: "
        f"expected {control_value}, got {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
