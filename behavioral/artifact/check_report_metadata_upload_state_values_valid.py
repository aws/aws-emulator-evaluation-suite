"""report-metadata-upload-state-values-valid."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "report-metadata-upload-state-values-valid"
GROUP = "data-plane"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Across a sample of the report catalog, each reportId matches its pattern, state is in its enum
    and version is a positive integer, and GetReportMetadata's uploadState, when present, is in
    its enum."""
    art = ctx.client("artifact")
    page = art.list_reports(maxResults=20)
    reports = page.get("reports", [])
    assert len(reports) > 0, "expected at least one report in the catalog"

    id_pattern = re.compile(r"^report-[a-zA-Z0-9]{16}$")
    valid_states = {"PUBLISHED", "UNPUBLISHED"}
    valid_upload_states = {"PROCESSING", "COMPLETE", "FAILED", "FAULT"}
    valid_acceptance_types = {"PASSTHROUGH", "EXPLICIT"}

    for r in reports:
        assert id_pattern.match(r["id"]), r["id"]
        assert r["state"] in valid_states, r["state"]
        assert r["acceptanceType"] in valid_acceptance_types, r["acceptanceType"]
        assert isinstance(r["version"], int) and r["version"] >= 1, r["version"]
        assert r["arn"].startswith("arn:"), r["arn"]
        assert r["name"], "report name must be non-empty"

        detail = art.get_report_metadata(reportId=r["id"])["reportDetails"]
        assert detail["uploadState"] in valid_upload_states, detail["uploadState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
