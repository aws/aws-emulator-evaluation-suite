"""deploy-guardduty-detector-cfn-active-behavior."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-guardduty-detector-cfn-active-behavior"
GROUP = "state-machine"
SERVICES = ["guardduty"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  GDDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES
"""


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A GuardDuty Detector deployed via CloudFormation is not just
    CREATE_COMPLETE -- it is a genuinely ACTIVE detector: GetDetector confirms
    ENABLED status, and CreateSampleFindings/ListFindings against it actually work."""
    gd = ctx.client("guardduty")
    if gd.list_detectors().get("DetectorIds", []):
        raise AssertionError(
            "unreachable: GuardDuty allows only one detector per account/region and "
            "this account/region already has one (from another concurrently running "
            "check or a prior leftover) -- the CFN stack's AWS::GuardDuty::Detector "
            "resource would fail to create a second one. Re-run in a clean "
            "account/region to exercise this."
        )

    stack_name, detector_id_holder = _deploy_cfn(ctx, _TEMPLATE)
    detector_id = _physical_id(ctx, stack_name, "GDDetector")
    detector_id_holder.append(detector_id)

    detector = gd.get_detector(DetectorId=detector_id)
    assert detector["Status"] == "ENABLED", (
        f"expected ENABLED, got {detector['Status']!r} for detector {detector_id}"
    )
    assert detector["FindingPublishingFrequency"] == "FIFTEEN_MINUTES", (
        "CFN-templated FindingPublishingFrequency was not applied: expected "
        f"FIFTEEN_MINUTES, got {detector['FindingPublishingFrequency']!r}"
    )

    gd.create_sample_findings(DetectorId=detector_id)
    ids = _poll_finding_ids(ctx, gd, detector_id)
    assert len(ids) > 0, (
        f"ListFindings never returned any finding for detector {detector_id} after "
        "CreateSampleFindings -- the CFN-deployed detector is not genuinely active"
    )


# ===== helpers =====
def _deploy_cfn(ctx, template_body: str) -> tuple[str, list[str]]:
    cfn = ctx.client("cloudformation")
    gd = ctx.client("guardduty")
    stack_name = ctx.unique_name("sim2real-gd-detector-")
    detector_id_holder: list[str] = []

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        if detector_id_holder:
            from botocore.exceptions import ClientError

            try:
                gd.get_detector(DetectorId=detector_id_holder[0])
            except ClientError as e:
                # GuardDuty answers a deleted detector with BadRequestException; anything else fails.
                if e.response["Error"]["Code"] != "BadRequestException":
                    raise
            else:
                raise AssertionError(
                    f"detector {detector_id_holder[0]} still answers GetDetector after "
                    "the CFN stack that created it was deleted"
                )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    return stack_name, detector_id_holder


def _physical_id(ctx, stack_name: str, logical_id: str) -> str:
    cfn = ctx.client("cloudformation")
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    for resource in resources:
        if resource["LogicalResourceId"] == logical_id:
            return resource["PhysicalResourceId"]
    raise AssertionError(f"resource {logical_id} not found in stack {stack_name}")


def _poll_finding_ids(ctx, gd, detector_id: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ids = gd.list_findings(DetectorId=detector_id).get("FindingIds", [])
        if ids:
            return ids
        time.sleep(1.0)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
