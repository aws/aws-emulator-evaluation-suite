"""list-workloads-includes-known-workload."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "list-workloads-includes-known-workload"
GROUP = "discovery"
SERVICES = ["launch-wizard"]

_NAME_RE = re.compile(r"^[A-Za-z][a-zA-Z0-9-_]*$")
_VALID_STATUSES = {"ACTIVE", "INACTIVE", "DISABLED", "DELETED"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkloads returns a non-empty catalog of well-formed entries with at least one ACTIVE workload,
    including the documented workload "SAP" (displayName "SAP", status ACTIVE)."""
    lw = ctx.client("launch-wizard")
    resp = lw.list_workloads(maxResults=100)
    workloads = resp.get("workloads", [])
    assert len(workloads) > 0, "expected the built-in Launch Wizard workload catalog to be non-empty"

    by_name = {}
    active_count = 0
    for w in workloads:
        assert _NAME_RE.match(w["workloadName"]), f"workloadName {w['workloadName']!r} violates naming pattern"
        assert w["status"] in _VALID_STATUSES, f"unexpected workload status {w['status']!r}"
        assert isinstance(w.get("displayName"), str) and w["displayName"], "displayName must be a non-empty string"
        by_name[w["workloadName"]] = w
        if w["status"] == "ACTIVE":
            active_count += 1

    assert active_count > 0, "expected at least one ACTIVE workload in the catalog"

    sap = by_name.get("SAP")
    assert sap is not None, f"expected the known workload 'SAP' in the catalog, got {sorted(by_name)}"
    assert sap["displayName"] == "SAP", f"expected SAP displayName 'SAP', got {sap['displayName']!r}"
    assert sap["status"] == "ACTIVE", f"expected SAP to be ACTIVE, got {sap['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
