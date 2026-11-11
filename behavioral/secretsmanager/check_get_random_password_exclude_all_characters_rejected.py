"""get-random-password-exclude-all-characters-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-random-password-exclude-all-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRandomPassword excluding every character class (upper, lower, numbers, punctuation, no
    IncludeSpace) is rejected with InvalidRequestException instead of returning an empty
    password; an unconstrained request still returns the default 32 characters."""
    sm = ctx.client("secretsmanager")

    err = _error(
        lambda: sm.get_random_password(
            ExcludeUppercase=True,
            ExcludeLowercase=True,
            ExcludeNumbers=True,
            ExcludePunctuation=True,
        )
    )
    assert err.get("Code") == "InvalidRequestException", f"expected InvalidRequestException, got {err!r}"
    assert err.get("Message") == "All characters have been excluded from selection.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    # 32 is the documented default PasswordLength.
    result = sm.get_random_password()
    actual_len = len(result["RandomPassword"])
    assert actual_len == 32, f"expected default password length 32, got {actual_len}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
