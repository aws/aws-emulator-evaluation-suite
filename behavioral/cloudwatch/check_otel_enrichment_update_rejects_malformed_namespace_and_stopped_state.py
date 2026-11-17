"""otel-enrichment-update-rejects-malformed-namespace-and-stopped-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "otel-enrichment-update-rejects-malformed-namespace-and-stopped-state"
GROUP = "otel-enrichment"
SERVICES = ["cloudwatch"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _restore(cw, status: str, include: list, exclude: list):
    if status != "Running":
        cw.stop_otel_enrichment()
    else:
        cw.update_otel_enrichment(IncludeFilters=include, ExcludeFilters=exclude)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:cloudwatch-otel-enrichment",
)
def run(ctx) -> None:
    """UpdateOTelEnrichment rejects a namespace filter starting with ':' and, once enrichment is
    stopped, rejects any update with the same not-found it gives a never-started account."""
    cw = ctx.client("cloudwatch")

    original = cw.get_otel_enrichment()
    original_status = original["Status"]
    original_include = original.get("IncludeFilters", [])
    original_exclude = original.get("ExcludeFilters", [])
    ctx.on_cleanup(lambda: _restore(cw, original_status, original_include, original_exclude))

    ns_good = ctx.unique_name("Sim2RealOTelNsGood")
    ns_bad = ":" + ctx.unique_name("Sim2RealOTelNsBad")
    ns_after = ctx.unique_name("Sim2RealOTelNsAfter")

    if original_status != "Running":
        cw.start_otel_enrichment(IncludeFilters=[{"Namespace": ns_good}])
    else:
        cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_good}], ExcludeFilters=[])

    baseline = cw.get_otel_enrichment()
    assert baseline["IncludeFilters"] == [{"Namespace": ns_good}], (
        f"expected the positive control's filter to be in place, got {baseline.get('IncludeFilters')!r}"
    )

    # Negative 1: a namespace filter whose Namespace starts with ':' is always invalid --
    # there is no neighbouring input for it to become valid under.
    code, message = _error(lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_bad}]))
    assert code == "ValidationError", f"expected ValidationError, got {code}: {message!r}"
    expected_message = (
        f"1 validation error detected: Value '{ns_bad}' at 'includeFilters.1.member.namespace' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: [^:].*"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_rejection = cw.get_otel_enrichment()
    assert after_rejection["IncludeFilters"] == [{"Namespace": ns_good}], (
        f"a rejected update must leave the filters untouched, got {after_rejection.get('IncludeFilters')!r}"
    )

    # Negative 2: once enrichment is stopped, the configuration this operation edits does not
    # exist -- the same not-found an account that never started enrichment would see.
    cw.stop_otel_enrichment()
    code, message = _error(lambda: cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_after}]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    expected_stopped_message = "OTel enrichment is not enabled for this account"
    assert message == expected_stopped_message, f"expected message {expected_stopped_message!r}, got {message!r}"

    stopped = cw.get_otel_enrichment()
    assert stopped["Status"] == "Stopped", f"expected Stopped, got {stopped['Status']!r}"

    # Restart (the twin of the broken thing) and confirm the identical update now succeeds.
    cw.start_otel_enrichment(IncludeFilters=[{"Namespace": ns_good}])
    cw.update_otel_enrichment(IncludeFilters=[{"Namespace": ns_after}])
    resumed = cw.get_otel_enrichment()
    assert resumed["Status"] == "Running", f"expected Running after restart, got {resumed['Status']!r}"
    assert resumed["IncludeFilters"] == [{"Namespace": ns_after}], (
        f"expected the identical update to succeed once running again, got {resumed.get('IncludeFilters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
