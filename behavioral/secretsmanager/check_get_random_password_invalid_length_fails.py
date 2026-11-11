"""get-random-password-invalid-length-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so accepting input
    AWS refuses fails loudly instead of reading as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects PasswordLength=100000, but it SUCCEEDED and returned {result!r}")

CHECK = "get-random-password-invalid-length-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRandomPassword rejects a PasswordLength outside [1, 4096] with ValidationException: the
    modelled range is enforced by request-shape validation, ahead of the operation's own errors.
    """
    sm = ctx.client("secretsmanager")
    err = _error(lambda: sm.get_random_password(PasswordLength=100000))
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_message = (
        "1 validation error detected: Value '100000' at 'passwordLength' failed to satisfy "
        "constraint: Member must have value less than or equal to 4096"
    )
    assert err.get("Message") == expected_message, f"unexpected message: {err.get('Message')!r}"

    # Positive control: an in-range length still succeeds -- the rejection above is specific to
    # the out-of-range value, not a general failure of the operation or the account/credentials.
    control = sm.get_random_password(PasswordLength=32)
    assert len(control["RandomPassword"]) == 32


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
