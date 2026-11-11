"""get-random-password-excluded-chars-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-random-password-excluded-chars-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRandomPassword whose ExcludeCharacters makes RequireEachIncludedType impossible is rejected."""
    sm = ctx.client("secretsmanager")

    # Numbers are not excluded (ExcludeNumbers defaults to False) so RequireEachIncludedType still
    # demands at least one digit, but ExcludeCharacters removes every possible digit -- impossible.
    err = _error(
        lambda: sm.get_random_password(PasswordLength=32, ExcludeCharacters="0123456789")
    )
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err!r}"
    assert err.get("Message") == "All characters of the desired type have been excluded.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    # Positive control: excluding a small, non-blocking set of characters still succeeds and is honored.
    control = sm.get_random_password(PasswordLength=32, ExcludeCharacters="!@#$%^&*")
    password = control["RandomPassword"]
    assert len(password) == 32, f"expected PasswordLength=32 to yield 32 chars, got {len(password)}"
    for ch in "!@#$%^&*":
        assert ch not in password, f"ExcludeCharacters={'!@#$%^&*'!r} was violated: {ch!r} in {password!r}"


def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, so a target
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
