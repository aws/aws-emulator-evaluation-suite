"""sample-findings-eventual-listability."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sample-findings-eventual-listability"
GROUP = "visibility-timeout-ttl"
SERVICES = ["guardduty"]

_FINDING_TYPE = "Backdoor:EC2/C&CActivity.B!DNS"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """After CreateSampleFindings, the number of findings of the sample type in
    ListFindings grows within a bounded wait."""
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx)

    criteria = {"Criterion": {"type": {"Equals": [_FINDING_TYPE]}}}
    count_before = len(_list_all_finding_ids(gd, detector_id, criteria))

    gd.create_sample_findings(DetectorId=detector_id, FindingTypes=[_FINDING_TYPE])

    deadline = time.monotonic() + 120.0
    count_after = count_before
    while time.monotonic() < deadline:
        count_after = len(_list_all_finding_ids(gd, detector_id, criteria))
        if count_after > count_before:
            break
        time.sleep(3.0)

    assert count_after > count_before, (
        f"ListFindings never reflected the new sample finding of type "
        f"{_FINDING_TYPE!r} (before={count_before}, after={count_after})"
    )


def _ensure_detector(ctx) -> str:
    from botocore.exceptions import ClientError

    gd = ctx.client("guardduty")
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
        created = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "BadRequestException":
            raise
        ids = gd.list_detectors().get("DetectorIds", [])
        if not ids:
            raise
        detector_id = ids[0]
        created = False
    if created:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _list_all_finding_ids(gd, detector_id: str, criteria: dict) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"DetectorId": detector_id, "FindingCriteria": criteria, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = gd.list_findings(**kwargs)
        ids.extend(resp.get("FindingIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
