"""catalog-describes-and-pagination."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "catalog-describes-and-pagination"
GROUP = 'read-only'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The account/catalog read surface: shapes are populated and Marker-based pagination advances
    instead of repeating the first page."""
    rs = ctx.client("redshift")
    attributes = _retrying(lambda: rs.describe_account_attributes())["AccountAttributes"]
    assert attributes, "expected at least one account attribute"
    for attribute in attributes:
        assert attribute["AttributeName"], attribute

    page1 = _retrying(lambda: rs.describe_cluster_versions(MaxRecords=20))
    versions = page1["ClusterVersions"]
    assert 0 < len(versions) <= 20, f"MaxRecords=20 must cap the page, got {len(versions)}"
    for version in versions:
        assert version["ClusterParameterGroupFamily"].startswith("redshift-"), version
    first_page = {(v["ClusterVersion"], v["ClusterParameterGroupFamily"]) for v in versions}
    marker = page1.get("Marker")
    if marker:
        page2 = _retrying(lambda: rs.describe_cluster_versions(MaxRecords=20, Marker=marker))
        second_page = {(v["ClusterVersion"], v["ClusterParameterGroupFamily"]) for v in page2["ClusterVersions"]}
        assert not (first_page & second_page), "a Marker page must not repeat the previous page's items"

    tracks = _retrying(lambda: rs.describe_cluster_tracks(MaxRecords=20))["MaintenanceTracks"]
    assert any(t["MaintenanceTrackName"] == "current" for t in tracks), tracks

    categories = _retrying(
        lambda: rs.describe_event_categories(SourceType="cluster")
    )["EventCategoriesMapList"]
    assert categories and all(c["SourceType"] == "cluster" for c in categories), categories

    events = _retrying(lambda: rs.describe_events(Duration=60, MaxRecords=20))
    assert isinstance(events["Events"], list), f"describe_events must return an Events list, got {events!r}"

    options = _retrying(
        lambda: rs.describe_orderable_cluster_options(MaxRecords=20)
    )["OrderableClusterOptions"]
    assert options, "expected orderable cluster options"
    for option in options:
        assert option["NodeType"], option
        assert option["AvailabilityZones"], option

    # ListRecommendations rejects an explicit MaxRecords here ("must be between 0 and 0"),
    # so it is called unfiltered.
    recommendations = _retrying(lambda: rs.list_recommendations())
    assert isinstance(recommendations["Recommendations"], list), (
        f"list_recommendations must return a Recommendations list, got {recommendations!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
