"""list-connectors-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-connectors-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectors rejects MaxResults 100001 and MaxResults 0 (sent with client-side validation off)
    with ValidationException and their exact messages, while an in-range MaxResults succeeds on both
    clients."""
    pcad = ctx.client("pca-connector-ad")

    # positive control: an in-range MaxResults value succeeds normally.
    control = pcad.list_connectors(MaxResults=10)
    assert "Connectors" in control

    over_code, over_message = _error_code(lambda: pcad.list_connectors(MaxResults=100001))
    assert over_code == "ValidationException", over_code
    assert over_message == (
        "1 validation error detected: Value '100001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 1000"
    ), over_message

    # the min:1 floor is enforced client-side by botocore itself (it mirrors the exact same
    # model constraint), so disable parameter validation to actually reach the service.
    unvalidated = ctx.client("pca-connector-ad", config=Config(parameter_validation=False))
    zero_code, zero_message = _error_code(lambda: unvalidated.list_connectors(MaxResults=0))
    assert zero_code == "ValidationException", zero_code
    assert zero_message == (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    ), zero_message

    # control still works through the unvalidated client too.
    control_raw = unvalidated.list_connectors(MaxResults=10)
    assert "Connectors" in control_raw


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(
        f"expected a rejection, but the call unexpectedly succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
