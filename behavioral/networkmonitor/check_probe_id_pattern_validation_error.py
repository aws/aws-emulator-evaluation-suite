"""probe-id-pattern-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "probe-id-pattern-validation-error"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProbe rejects a probeId that doesn't match ^probe-[a-z0-9A-Z-]{21,64}$ with
    ValidationException -- distinct from the ResourceNotFoundException a well-formed
    but nonexistent probeId gets (positive control, same file)."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"sim2real": "audit"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    # positive control: a well-formed but nonexistent probeId passes pattern
    # validation and reaches the resource lookup, so it fails differently
    well_formed_probe_id = "probe-" + "a" * 25
    positive = _error(lambda: nm.get_probe(monitorName=name, probeId=well_formed_probe_id))
    assert positive["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {positive['Code']!r}"
    expected = f"No existing probe {well_formed_probe_id} found for account {ctx.account} and monitorName {name}."
    assert positive["Message"] == expected, f"expected message {expected!r}, got {positive['Message']!r}"

    err = _error(lambda: nm.get_probe(monitorName=name, probeId="not-a-valid-probe-id"))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = "1 validation error detected: Value 'not-a-valid-probe-id' at 'probeId' failed to satisfy constraint: Member must satisfy regular expression pattern: probe-[a-z0-9A-Z-]{21,64}"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
