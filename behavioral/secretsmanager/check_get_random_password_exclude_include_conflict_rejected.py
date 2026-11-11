"""get-random-password-exclude-include-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-random-password-exclude-include-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

# Every character Secrets Manager draws from by default: upper/lower letters, digits, and
# the documented default punctuation set. Excluding all of them leaves nothing to draw from.
_DEFAULT_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRandomPassword rejects an ExcludeCharacters value covering every default character
    with InvalidParameterException instead of returning an unusable password, while an
    unconstrained request still returns a password of the requested length."""
    sm = ctx.client("secretsmanager")

    err = _error(
        lambda: sm.get_random_password(ExcludeCharacters=_DEFAULT_ALPHABET, PasswordLength=10)
    )
    # An invalid parameter value, not a resource-state conflict, so InvalidParameterException.
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err}"
    assert err.get("Message") == "All characters of the desired type have been excluded.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    ok = sm.get_random_password(PasswordLength=20)
    assert len(ok["RandomPassword"]) == 20, f"expected a 20-char password, got {ok['RandomPassword']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
