"""delete-supplemental-tax-registration-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-supplemental-tax-registration-not-found"
GROUP = "error-semantics"
SERVICES = ["taxsettings"]

_INVALID_AUTHORITY = "Provided authorityId is not valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSupplementalTaxRegistration refuses three authorityIds that name no registration, two malformed and
    one a well-formed UUID, each with ValidationException and the same exact message."""
    ts = ctx.client("taxsettings")

    bogus_authority = ctx.unique_name("sim2real-no-such-authority-")
    code, message = _error(lambda: ts.delete_supplemental_tax_registration(authorityId=bogus_authority))
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed authorityId, got {code!r}"
    )
    assert message == _INVALID_AUTHORITY, f"expected {_INVALID_AUTHORITY!r}, got {message!r}"

    # A second, differently-shaped malformed authorityId hits the same boundary.
    bogus_authority2 = "!!!not-a-real-authority!!!"
    code2, message2 = _error(lambda: ts.delete_supplemental_tax_registration(authorityId=bogus_authority2))
    assert code2 == "ValidationException", (
        f"expected ValidationException for a second malformed authorityId, got {code2!r}"
    )
    assert message2 == _INVALID_AUTHORITY, f"expected {_INVALID_AUTHORITY!r}, got {message2!r}"

    # Positive control: a syntactically plausible, service-id-shaped candidate
    # (a UUID -- not junk, not obviously malformed) hits the identical
    # boundary, proving the rejection isn't merely "garbage-looking string
    # rejected" but unconditional absence-of-any-registration on this account.
    plausible_authority = str(uuid.uuid4())
    code3, message3 = _error(lambda: ts.delete_supplemental_tax_registration(authorityId=plausible_authority))
    assert code3 == "ValidationException", (
        f"expected ValidationException for a plausible-looking but nonexistent authorityId, got {code3!r}"
    )
    assert message3 == _INVALID_AUTHORITY, f"expected {_INVALID_AUTHORITY!r}, got {message3!r}"


def _error(fn):
    """The rejected call's (code, message); an unexpected success raises, so an emulator that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


