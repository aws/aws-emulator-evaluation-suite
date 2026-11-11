"""put-account-configuration-expiry-events-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-configuration-expiry-events-roundtrip"
GROUP = "account-configuration"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:acm-account-configuration")
def run(ctx) -> None:
    """DaysBeforeExpiry round-trips via GetAccountConfiguration; reusing an IdempotencyToken with a
    different value raises ConflictException without mutating; an identical replay is accepted;
    a fresh token applies a new value."""
    acm = ctx.client("acm")

    original = acm.get_account_configuration().get("ExpiryEvents", {}).get("DaysBeforeExpiry", 45)
    ctx.on_cleanup(
        lambda: acm.put_account_configuration(
            ExpiryEvents={"DaysBeforeExpiry": original}, IdempotencyToken=_token()
        )
    )

    # DaysBeforeExpiry must be within 1..45, so 44 is the in-range alternative to 30.
    new_value = 30 if original != 30 else 44
    first_token = _token()
    acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": new_value}, IdempotencyToken=first_token)

    got = acm.get_account_configuration()
    assert got["ExpiryEvents"]["DaysBeforeExpiry"] == new_value, got

    # Reusing first_token with a DIFFERENT value is a parameter mismatch: ACM rejects it with
    # ConflictException (the API docs describe a silent replay) and the value does not move.
    replayed_value = 1 if new_value != 1 else 2
    try:
        acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": replayed_value}, IdempotencyToken=first_token)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"reusing IdempotencyToken={first_token!r} with a different value must be rejected, but it succeeded"
        )
    assert code == "ConflictException", (
        f"reusing IdempotencyToken={first_token!r} with a different value expected ConflictException, "
        f"got code={code!r}"
    )
    expected = "A different request with same idempotency token has already been processed."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after_conflict = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert after_conflict == new_value, (
        f"a rejected idempotency-token replay must not mutate the account: "
        f"expected DaysBeforeExpiry to remain {new_value}, got {after_conflict}"
    )

    # Replaying first_token with its ORIGINAL value is the identical request and succeeds.
    acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": new_value}, IdempotencyToken=first_token)
    after_identical_replay = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert after_identical_replay == new_value, after_identical_replay

    # The same replayed_value under a FRESH token is a genuinely new request and must apply.
    acm.put_account_configuration(ExpiryEvents={"DaysBeforeExpiry": replayed_value}, IdempotencyToken=_token())
    after_fresh = acm.get_account_configuration()["ExpiryEvents"]["DaysBeforeExpiry"]
    assert after_fresh == replayed_value, after_fresh


def _token() -> str:
    return uuid.uuid4().hex


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
