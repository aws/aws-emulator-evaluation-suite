"""filter-criteria-numeric-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-criteria-numeric-round-trip"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A Filter created with numeric range criteria (severity gte/lte) round-trips
    byte-identical through GetFilter, including the exact numeric boundaries."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx, gd)

    name = ctx.unique_name("sim2real-filter-")
    criteria = {
        "Criterion": {
            "severity": {"GreaterThanOrEqual": 4, "LessThanOrEqual": 8},
            "type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]},
        }
    }
    # NOTE: GuardDuty enforces that a new filter's Rank fit within the
    # contiguous ordering of the detector's *existing* filters (i.e. at most
    # current-filter-count + 1) -- not just the documented 1-100 bound. On a
    # detector with zero pre-existing filters, the only valid Rank is 1.
    gd.create_filter(
        DetectorId=detector_id,
        Name=name,
        Description="numeric round-trip check",
        Action="NOOP",
        Rank=1,
        FindingCriteria=criteria,
    )
    ctx.on_cleanup(lambda: _safe_delete_filter(gd, detector_id, name))

    got = gd.get_filter(DetectorId=detector_id, FilterName=name)

    assert got["Name"] == name
    assert got["Rank"] == 1
    assert got["Action"] == "NOOP"
    criterion = got["FindingCriteria"]["Criterion"]
    # The exact numeric boundaries we sent must survive unchanged (this is the
    # behavior under test). AWS may additionally echo the deprecated
    # integer-typed "Gte"/"Lte" aliases alongside the canonical
    # "GreaterThanOrEqual"/"LessThanOrEqual" fields, so we assert on the
    # specific values rather than exact dict/key-set equality.
    severity = criterion["severity"]
    assert severity["GreaterThanOrEqual"] == 4, severity
    assert severity["LessThanOrEqual"] == 8, severity
    assert criterion["type"]["Equals"] == ["Recon:EC2/PortProbeUnprotectedPort"], criterion["type"]
    # Exactly the two top-level criteria fields we sent -- no fields injected or lost.
    assert set(criterion.keys()) == {"severity", "type"}

    # Delete proves gone and unusable: an independent read returns the specific not-found
    # code, and a mutation on the dead filter fails the same way.
    gd.delete_filter(DetectorId=detector_id, FilterName=name)
    err = _error(lambda: gd.get_filter(DetectorId=detector_id, FilterName=name))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException on dead filter read, got {err}"
    assert err["Message"] == "The request is rejected since no such resource found.", f"unexpected dead filter read message {err['Message']!r}"
    err = _error(lambda: gd.update_filter(DetectorId=detector_id, FilterName=name, Rank=1))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException on dead filter update, got {err}"
    assert err["Message"] == "The request is rejected because the given filter name is invalid.", (
        f"unexpected dead filter update message {err['Message']!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not be reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_filter(gd, detector_id, name):
    try:
        gd.delete_filter(DetectorId=detector_id, FilterName=name)
    except ClientError as exc:
        # GuardDuty reports a filter name that is already gone as BadRequestException.
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise


def _ensure_detector(ctx, gd) -> str:
    """Create a GuardDuty detector, or fall back to the account's existing one.

    GuardDuty allows only one detector per account/region, so a concurrently
    running check (or a leftover from a previous run) may already own it.
    """
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
        return detector_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "BadRequestException":
            raise
        existing = gd.list_detectors().get("DetectorIds", [])
        if not existing:
            raise
        return existing[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
