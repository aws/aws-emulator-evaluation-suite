"""create-sample-findings-generates-server-side-findings."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-sample-findings-generates-server-side-findings"
GROUP = "server-side"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateSampleFindings triggers server-side finding generation that becomes visible via
    ListFindings/GetFindings without any additional detection action from the caller, and the
    generated findings are recognizably marked as synthetic samples."""
    gd = ctx.client("guardduty")
    detector_id = gd.create_detector(
        Enable=True, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    gd.create_sample_findings(DetectorId=detector_id)

    finding_ids = _poll_until_findings(gd, detector_id, timeout_s=90.0)
    assert finding_ids, "no sample findings appeared via ListFindings within the timeout"

    findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:20])["Findings"]
    assert findings, "GetFindings returned no findings for the sample finding IDs"
    sample_marked = 0
    for finding in findings:
        assert finding["AccountId"], f"sample finding {finding.get('Id')} has an empty AccountId"
        assert finding["Type"], f"sample finding {finding.get('Id')} has an empty Type"
        assert finding.get("Title"), "sample finding is missing a Title"
        additional_info = finding.get("Service", {}).get("AdditionalInfo")
        value = additional_info.get("Value") if isinstance(additional_info, dict) else additional_info
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError):
                parsed = {}
            if parsed.get("sample") is True:
                sample_marked += 1
    assert sample_marked > 0, (
        "no sample finding carried the documented Service.AdditionalInfo "
        '{"sample": true} marker identifying it as synthetic'
    )


def _poll_until_findings(gd, detector_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = gd.list_findings(DetectorId=detector_id, MaxResults=50).get("FindingIds", [])
        if ids:
            return ids
        time.sleep(3.0)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
