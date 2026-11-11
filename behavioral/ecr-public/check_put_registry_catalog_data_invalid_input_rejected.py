"""put-registry-catalog-data-invalid-input-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "put-registry-catalog-data-invalid-input-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client pins that
    region; ctx.client keeps an emulator run on the emulator's endpoint."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-public-registry-catalog")
def run(ctx) -> None:
    """PutRegistryCatalogData with a displayName over the 100-char limit is rejected with
    InvalidParameterException, leaves the previous display name untouched, and a
    within-limit call in the same file still succeeds (positive control)."""
    ecrp = _ecrpub_client(ctx)

    baseline = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName", "")

    def _restore():
        ecrp.put_registry_catalog_data(displayName=baseline)

    ctx.on_cleanup(_restore)

    # Break: displayName exceeds the documented max length of 100 characters.
    too_long = "x" * 101
    error = _error(lambda: ecrp.put_registry_catalog_data(displayName=too_long))
    assert error["Code"] == "InvalidParameterException", f"expected InvalidParameterException, got {error!r}"
    expected = "Invalid parameter at 'displayName' failed to satisfy constraint: 'Member must have length less than or equal to 100'"
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    # Effect absent: the previous display name is unchanged (not partially applied).
    after_reject = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName", "")
    assert after_reject == baseline, "rejected call must not mutate registry catalog data"

    # Positive control: a within-limit value is accepted and persisted.
    valid_name = ctx.unique_name("sim2real-regdisplay-")[:100]
    ecrp.put_registry_catalog_data(displayName=valid_name)
    after_accept = ecrp.get_registry_catalog_data()["registryCatalogData"].get("displayName", "")
    assert after_accept == valid_name, f"expected persisted displayName {valid_name!r}, got {after_accept!r}"


def _error(fn) -> Any:
    """Call fn(); return its botocore Error (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected InvalidParameterException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
