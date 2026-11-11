"""registry-catalog-display-name-round-trip-and-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-catalog-display-name-round-trip-and-limit"
GROUP = 'registry'
SERVICES = ['ecr-public']

# RegistryDisplayName has @length max 100; botocore does not validate max, so the
# rejection is server-side.
_DISPLAY_NAME_MAX = 100

# PutRegistryCatalogData mutates the account's one registry (displayName is the gallery author
# name), so the prior value is saved and restored; run serially against an account.
_SYNTHETIC_DISPLAY_NAME = "SIM2REAL-SYNTHETIC-TEST-REGISTRY"

def _err(fn):
    """Call fn() and return the botocore Error (Code and Message); raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _display_name(ecr):
    """The registry's current displayName, or None if the member is absent."""
    return ecr.get_registry_catalog_data()["registryCatalogData"].get("displayName")


def _restore(ecr, original):
    """Put the account's registry displayName back to `original`.

    RegistryDisplayName permits the empty string (@length min 0), which is the closest reachable
    equivalent of "was never set" — the API models no way to unset the member.
    """
    ecr.put_registry_catalog_data(displayName=original if original is not None else "")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """The registry displayName round-trips verbatim at its 100-character maximum; 101 characters
    is rejected with InvalidParameterException and its exact message, leaving the value intact.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_PutRegistryCatalogData.html
    """
    ecr = ctx.client("ecr-public")

    original = _display_name(ecr)
    # Registered before the first mutation, so a killed harness still restores the account.
    ctx.on_cleanup(lambda: _restore(ecr, original))

    # A per-run value can never coincide with the stored one, so the round-trip is not vacuous.
    at_limit = (
        ctx.unique_name(_SYNTHETIC_DISPLAY_NAME + "-") + "X" * _DISPLAY_NAME_MAX
    )[:_DISPLAY_NAME_MAX]
    assert len(at_limit) == _DISPLAY_NAME_MAX
    assert at_limit != original, (
        "the at-limit value must differ from what was already stored, or the round-trip proves "
        f"nothing: {at_limit!r}"
    )

    put = ecr.put_registry_catalog_data(displayName=at_limit)
    assert put["registryCatalogData"].get("displayName") == at_limit, (
        f"PutRegistryCatalogData must echo the {_DISPLAY_NAME_MAX}-character displayName verbatim; "
        f"got {put['registryCatalogData'].get('displayName')!r}"
    )
    assert _display_name(ecr) == at_limit, (
        f"GetRegistryCatalogData must read back the stored displayName verbatim; got "
        f"{_display_name(ecr)!r}"
    )

    over = at_limit + "Y"
    assert len(over) == _DISPLAY_NAME_MAX + 1
    error = _err(lambda: ecr.put_registry_catalog_data(displayName=over))
    assert error["Code"] == "InvalidParameterException", (
        f"a {_DISPLAY_NAME_MAX + 1}-character displayName is one past the @length max "
        f"{_DISPLAY_NAME_MAX} and must be rejected with InvalidParameterException; got {error!r}"
    )
    expected = (
        "Invalid parameter at 'displayName' failed to satisfy constraint: "
        f"'Member must have length less than or equal to {_DISPLAY_NAME_MAX}'"
    )
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"
    assert _display_name(ecr) == at_limit, (
        "the rejected over-limit write mutated account-global state; displayName is now "
        f"{_display_name(ecr)!r}, expected the previous {at_limit!r}"
    )

    control = _SYNTHETIC_DISPLAY_NAME
    assert len(control) <= _DISPLAY_NAME_MAX
    ecr.put_registry_catalog_data(displayName=control)
    assert _display_name(ecr) == control, (
        f"the control in-limit write did not take effect: {_display_name(ecr)!r} != {control!r}"
    )

    # Restored in-band as well, so the account is clean even if teardown is skipped.
    _restore(ecr, original)
    restored = _display_name(ecr)
    expected = original if original is not None else ""
    assert restored in (expected, original), (
        f"failed to restore the account's registry displayName: it is now {restored!r}, "
        f"expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
