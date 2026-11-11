"""deploy-detector-cfn-behaves."""
from __future__ import annotations

CHECK = "deploy-detector-cfn-behaves"
GROUP = "deploy"
SERVICES = ["guardduty"]

from behavioral_harness import tags

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: SIX_HOURS
      Tags:
        - Key: sim2real:managed
          Value: "true"
        - Key: sim2real:prefix
          Value: sim2real-behav
Outputs:
  DetectorId:
    Value: !Ref Detector
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A CloudFormation-deployed detector is ENABLED with the templated SIX_HOURS frequency; a filter on
    it is created, read and deleted (GetFilter then fails with the exact BadRequestException), and after
    stack deletion GetDetector fails the same way and ListDetectors no longer lists the detector."""
    gd = ctx.client("guardduty")
    # GuardDuty allows only one detector per account per Region, so we cannot safely
    # create a second one via CloudFormation if this account already has one enabled.
    if gd.list_detectors().get("DetectorIds", []):
        raise AssertionError(
            "a GuardDuty detector already exists in this account/Region; GuardDuty allows "
            "only one detector per account per Region (see CreateDetector docs), so deploying "
            "a second one via CloudFormation would fail. This check needs a account/Region "
            "with no pre-existing detector to exercise CFN-driven detector creation."
        )

    stack_name, outputs = _deploy_cfn(ctx, _TEMPLATE)
    detector_id = outputs["DetectorId"]

    detector = gd.get_detector(DetectorId=detector_id)
    assert detector["Status"] == "ENABLED", f"expected ENABLED, got {detector['Status']!r}"
    assert detector["FindingPublishingFrequency"] == "SIX_HOURS", (
        f"expected SIX_HOURS, got {detector['FindingPublishingFrequency']!r}"
    )

    filter_name = ctx.unique_name("sim2real-behav-filter-")
    gd.create_filter(
        DetectorId=detector_id,
        Name=filter_name,
        FindingCriteria={"Criterion": {"severity": {"Gte": 4}}},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    got = gd.get_filter(DetectorId=detector_id, FilterName=filter_name)
    assert got["Name"] == filter_name, f"expected {filter_name!r}, got {got['Name']!r}"
    assert got["FindingCriteria"]["Criterion"]["severity"]["Gte"] == 4, (
        f"expected severity Gte 4, got {got['FindingCriteria']['Criterion']['severity']}"
    )

    gd.delete_filter(DetectorId=detector_id, FilterName=filter_name)
    remaining = gd.list_filters(DetectorId=detector_id)["FilterNames"]
    assert filter_name not in remaining, f"{filter_name!r} still in {remaining!r} after delete"
    err, message = _expect_error(lambda: gd.get_filter(DetectorId=detector_id, FilterName=filter_name))
    assert err == "BadRequestException", f"expected BadRequestException reading a deleted filter, got {err!r}"
    expected_message = "The request is rejected since no such resource found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # teardown asserted: deleting the stack must actually remove the detector at the
    # destination, not just report DELETE_COMPLETE on the stack.
    _delete_stack(ctx, stack_name)
    err, message = _expect_error(lambda: gd.get_detector(DetectorId=detector_id))
    assert err == "BadRequestException", f"expected BadRequestException reading a deleted detector, got {err!r}"
    expected_message = "The request is rejected because the input detectorId is not owned by the current account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    remaining_detectors = gd.list_detectors().get("DetectorIds", [])
    assert detector_id not in remaining_detectors, f"{detector_id!r} still in {remaining_detectors!r} after stack teardown"


def _expect_error(call) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _deploy_cfn(ctx, template_body: str, parameters=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-gd-detector-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM"],
        "Tags": [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    }
    if parameters:
        kwargs["Parameters"] = parameters
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
