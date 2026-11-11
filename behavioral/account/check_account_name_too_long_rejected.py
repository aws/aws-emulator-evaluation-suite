"""account-name-too-long-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-name-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:account-name")
def run(ctx) -> None:
    """PutAccountName with a name over the 50-character limit is rejected with ValidationException,
    the account name is left unchanged, and a valid-length name still succeeds (positive control)."""
    account = ctx.client("account")

    original_name = account.get_account_information()["AccountName"]
    ctx.on_cleanup(lambda: account.put_account_name(AccountName=original_name))

    too_long_name = "sim2real-behav-" + ("x" * 40)  # 55 chars, over the 50-char max
    assert len(too_long_name) > 50

    code, message = _error_code(lambda: account.put_account_name(AccountName=too_long_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        f'[string "{too_long_name}" is too long (length: {len(too_long_name)}, maximum allowed: 50)]'
    ), message

    # the effect must be absent: name on file is still the original
    after_reject = account.get_account_information()["AccountName"]
    assert after_reject == original_name, (
        f"AccountName changed despite rejection: expected {original_name!r}, got {after_reject!r}"
    )

    # positive control: a valid-length name still succeeds (propagation to reads can lag
    # the write, so poll with a bounded timeout instead of asserting immediately)
    valid_name = ctx.unique_name("sim2real-behav-len-")
    assert len(valid_name) <= 50
    account.put_account_name(AccountName=valid_name)

    deadline = time.time() + 60
    seen = None
    while time.time() < deadline:
        seen = account.get_account_information()["AccountName"]
        if seen == valid_name:
            break
        time.sleep(3)
    assert seen == valid_name, f"AccountName never converged to {valid_name!r}, last saw {seen!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
