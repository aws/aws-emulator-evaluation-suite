"""report-version-listing-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "report-version-listing-consistency"
GROUP = "data-plane"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListReportVersions for a multi-version report returns a duplicate-free version set, stable across
    repeated reads, and GetReportMetadata for one version returns exactly that version."""
    art = ctx.client("artifact")

    multi_versioned = None
    versions = None
    scanned = 0
    token = None
    # Scan the catalog for a report that has more than one published version;
    # cap the scan so this stays cheap against a large real-AWS catalog.
    while scanned < 60 and multi_versioned is None:
        kwargs = {"maxResults": 20}
        if token:
            kwargs["nextToken"] = token
        page = art.list_reports(**kwargs)
        for summary in page.get("reports", []):
            scanned += 1
            candidate = art.list_report_versions(reportId=summary["id"]).get("reports", [])
            if len(candidate) > 1:
                multi_versioned = summary["id"]
                versions = candidate
                break
        token = page.get("nextToken")
        if not token:
            break

    if multi_versioned is None:
        raise AssertionError(
            "no report in the first 60 catalog entries has more than one version; "
            "cannot verify multi-version listing/pinning semantics"
        )

    version_numbers = [v["version"] for v in versions]
    assert len(version_numbers) == len(set(version_numbers)), "duplicate version numbers returned"

    # ListReportVersions has no sort-order contract and returns versions in varying order,
    # so the version SET must be stable across independent reads.
    repeat_numbers = {v["version"] for v in art.list_report_versions(reportId=multi_versioned).get("reports", [])}
    assert repeat_numbers == set(version_numbers), (
        "ListReportVersions returned a different version set on a repeat read: "
        f"{sorted(version_numbers)} vs {sorted(repeat_numbers)}"
    )

    target_version = max(version_numbers)
    pinned = art.get_report_metadata(reportId=multi_versioned, reportVersion=target_version)[
        "reportDetails"
    ]
    assert pinned["version"] == target_version, f"expected pinned version {target_version}, got {pinned['version']}"
    assert pinned["id"] == multi_versioned, f"expected pinned id {multi_versioned}, got {pinned['id']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
