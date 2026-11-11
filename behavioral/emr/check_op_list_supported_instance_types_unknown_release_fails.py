"""op-list-supported-instance-types-unknown-release-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-list-supported-instance-types-unknown-release-fails"
GROUP = 'overly-permissive'
SERVICES = ['emr']

GOOD_RELEASE_LABEL = "emr-6.15.0"

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: ListSupportedInstanceTypes must reject an unknown
    release label rather than returning a generic instance catalogue."""
    emr = ctx.client("emr")

    control = emr.list_supported_instance_types(ReleaseLabel=GOOD_RELEASE_LABEL)
    assert control["SupportedInstanceTypes"], (
        f"positive control failed: {GOOD_RELEASE_LABEL} returned no instance types, "
        "so the rejection below cannot be told apart from rejecting every release label"
    )

    code, message = _error(
        lambda: emr.list_supported_instance_types(ReleaseLabel="emr-99.99.0")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "The supplied release label is invalid: emr-99.99.0.", (
        f"expected AWS's exact invalid-release-label message, got {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
