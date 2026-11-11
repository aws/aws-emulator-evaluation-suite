"""deploy-sar-changeset-for-unpublished-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sar-changeset-for-unpublished-version-rejected"
GROUP = "deploy-serverlessrepo-changeset"
SERVICES = ["cloudformation", "serverlessrepo", "sqs"]

_CHANGE_SET_WAIT_S = 180
# Cleanups share one 60s bound, so teardown observes the delete rather than waiting it out.
_DELETE_OBSERVE_S = 20
_CONVERGE_S = 60

_SAM_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::Serverless-2016-10-31",
    "Parameters": {"QueueNameParam": {"Type": "String"}},
    "Resources": {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
        }
    },
    "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
}


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """SAR rejects a change set for an unpublished version with NotFoundException and leaves no
    stack behind, not even a REVIEW_IN_PROGRESS shell; the published version succeeds."""
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")

    app_name = ctx.unique_name("sim2real-xsvc-sarneg-")
    created = sar.create_application(
        Name=app_name,
        Author="sim2real-xsvc",
        Description="sim2real cross-service SAR version-rejection check",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
        SemanticVersion="1.0.0",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: sar.delete_application(ApplicationId=app_id))

    # SAR's version list is eventually consistent after a publish, so converge on it rather than
    # reading it once: this is the premise of the rejection below, not the claim under test.
    _await_versions(sar, app_id, ["1.0.0"])

    # ---- negative: a version this application never published
    missing_stack = ctx.unique_name("sim2real-xsvc-sarnostk-")
    try:
        cut = sar.create_cloud_formation_change_set(
            ApplicationId=app_id,
            StackName=missing_stack,
            SemanticVersion="9.9.9",
            ParameterOverrides=[
                {"Name": "QueueNameParam", "Value": ctx.unique_name("sim2real-xsvc-sarq-")}
            ],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
    else:
        ctx.on_cleanup(lambda: _delete_stack(cfn, cut["StackId"]))
        raise AssertionError(
            f"change set for unpublished version 9.9.9 succeeded: {cut['ChangeSetId']!r}"
        )

    assert code == "NotFoundException", f"rejection code is {code!r}, expected NotFoundException"
    assert status == 404, f"rejection status is {status!r}, expected 404"
    expected = f"Application {app_id} does not have a version 9.9.9"
    assert message == expected, f"rejection message {message!r} != {expected!r}"

    # The refusal left nothing behind: SAR would have deployed into `serverlessrepo-<name>`.
    assert not _stack_exists(cfn, f"serverlessrepo-{missing_stack}"), (
        f"a stack serverlessrepo-{missing_stack!r} exists after the change set was rejected"
    )

    # ---- positive control: same call, published version
    good_stack = ctx.unique_name("sim2real-xsvc-sarokstk-")
    cut = sar.create_cloud_formation_change_set(
        ApplicationId=app_id,
        StackName=good_stack,
        SemanticVersion="1.0.0",
        ParameterOverrides=[
            {"Name": "QueueNameParam", "Value": ctx.unique_name("sim2real-xsvc-sarq-")}
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, cut["StackId"]))
    described = _await_change_set(cfn, cut["ChangeSetId"])
    assert described["Status"] == "CREATE_COMPLETE", (
        f"control change set is {described['Status']!r}: {described.get('StatusReason')!r}"
    )
    assert described["ExecutionStatus"] == "AVAILABLE", (
        f"control change set is not executable: {described['ExecutionStatus']!r}"
    )
    assert _stack_exists(cfn, f"serverlessrepo-{good_stack}"), (
        f"control change set cut no stack serverlessrepo-{good_stack!r}"
    )


def _await_versions(sar, app_id: str, expected: list[str]) -> None:
    deadline = time.time() + _CONVERGE_S
    listed: list[str] = []
    while time.time() < deadline:
        listed = [
            v["SemanticVersion"]
            for v in sar.list_application_versions(ApplicationId=app_id)["Versions"]
        ]
        if listed == expected:
            return
        time.sleep(3)
    raise AssertionError(
        f"application published {listed!r} after {_CONVERGE_S}s, expected {expected!r}"
    )


def _stack_exists(cfn, stack_name: str) -> bool:
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return False
        raise
    return bool(stacks) and stacks[0]["StackStatus"] != "DELETE_COMPLETE"


def _await_change_set(cfn, change_set_id: str) -> dict:
    deadline = time.time() + _CHANGE_SET_WAIT_S
    described = cfn.describe_change_set(ChangeSetName=change_set_id)
    while described["Status"] in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
        assert time.time() < deadline, (
            f"change set {change_set_id!r} stuck in {described['Status']!r} after "
            f"{_CHANGE_SET_WAIT_S}s"
        )
        time.sleep(3)
        described = cfn.describe_change_set(ChangeSetName=change_set_id)
    return described


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack, waiting only until CloudFormation accepts and starts the delete.

    Cleanups share one 60s bound and the application delete still runs after this one (LIFO);
    a DELETE_IN_PROGRESS stack finishes on its own, an undeleted application would leak.
    """
    cfn.delete_stack(StackName=stack_id)
    deadline = time.time() + _DELETE_OBSERVE_S
    while time.time() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_id)["Stacks"]
        if stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        if stacks[0]["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_id!r} failed to delete: {stacks[0].get('StackStatusReason')!r}"
            )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
