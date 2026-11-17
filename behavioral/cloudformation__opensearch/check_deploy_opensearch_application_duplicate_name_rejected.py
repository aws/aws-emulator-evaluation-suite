"""deploy-opensearch-application-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-opensearch-application-duplicate-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "opensearch"]

_CREATE_FAILED_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})


def _wait_stack(cfn, stack_id: str, timeout_s: float = 300.0, interval_s: float = 3.0) -> str:
    """Poll DescribeStacks by StackId until the status leaves an IN_PROGRESS state; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} still {status!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_stack(cfn, stack_id: str) -> None:
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status not in _TERMINAL:
        status = _wait_stack(cfn, stack_id, timeout_s=300.0)
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(cfn, stack_id, timeout_s=300.0)
    assert final == "DELETE_COMPLETE", f"stack {stack_id!r} delete ended {final!r}"


def _stack_events(cfn, stack_id: str) -> list[dict]:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _create_failed_rows(events: list[dict]) -> list[tuple[str, str]]:
    """``(LogicalResourceId, ResourceStatusReason)`` of every CREATE_FAILED event."""
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason", "")) for e in events
            if e["ResourceStatus"] == "CREATE_FAILED"]


def _applications_named(osc, name: str) -> list[dict]:
    matches: list[dict] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = osc.list_applications(**kwargs)
        matches.extend(s for s in page["ApplicationSummaries"] if s["name"] == name)
        token = page.get("nextToken")
        if not token:
            return matches


def _template(app_name: str, tag_value: str) -> str:
    return f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  App:
    Type: AWS::OpenSearchService::Application
    Properties:
      Name: {app_name}
      DataSources: []
      Tags:
        - Key: sim2real
          Value: {tag_value}
Outputs:
  AppId:
    Value: !GetAtt App.Id
"""


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CloudFormation stack declaring an AWS::OpenSearchService::Application with an
    already-active application's Name fails validation before provisioning it, leaving the first
    application the only one of that name, while a stack naming it something new deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-opensearchservice-application.html
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")

    shared_name = ctx.unique_name("sim2real-osapp-")
    first_stack_name = ctx.unique_name("sim2real-osdup1-")
    first_id = cfn.create_stack(
        StackName=first_stack_name,
        TemplateBody=_template(shared_name, first_stack_name),
        Tags=[{"Key": "sim2real", "Value": first_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, first_id))
    status = _wait_stack(cfn, first_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"first stack ended {status!r}, expected CREATE_COMPLETE"
    first_app_id = _applications_named(osc, shared_name)[0]["id"]
    assert osc.get_application(id=first_app_id)["status"] == "ACTIVE", (
        f"the first application {first_app_id!r} is not ACTIVE before the second stack is tried"
    )

    second_stack_name = ctx.unique_name("sim2real-osdup2-")
    second_id = cfn.create_stack(
        StackName=second_stack_name,
        TemplateBody=_template(shared_name, second_stack_name),
        Tags=[{"Key": "sim2real", "Value": second_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, second_id))
    status = _wait_stack(cfn, second_id, timeout_s=300.0)
    assert status == "ROLLBACK_COMPLETE", f"second stack ended {status!r}, expected ROLLBACK_COMPLETE"

    rows = _create_failed_rows(_stack_events(cfn, second_id))
    assert rows == [(second_stack_name, _CREATE_FAILED_REASON)], (
        f"CREATE_FAILED rows {rows!r}, expected exactly one on the stack itself with the "
        f"validation reason {_CREATE_FAILED_REASON!r}"
    )

    try:
        detail = cfn.describe_stack_resource(StackName=second_id, LogicalResourceId="App")
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        want = ("ValidationError", f"Resource App does not exist for stack {second_id}")
        assert got == want, f"DescribeStackResource error {got!r}, expected {want!r}"
    else:
        raise AssertionError(f"expected no App resource on the rolled-back stack, got {detail!r}")

    matches = _applications_named(osc, shared_name)
    assert [a["id"] for a in matches] == [first_app_id], (
        f"applications named {shared_name!r}: {matches!r}, expected only the first one, {first_app_id!r}"
    )
    assert osc.get_application(id=first_app_id)["status"] == "ACTIVE", (
        f"the first application {first_app_id!r} is no longer ACTIVE after the rejected duplicate"
    )

    control_name = ctx.unique_name("sim2real-osapp-")
    control_stack_name = ctx.unique_name("sim2real-oscontrol-")
    control_id = cfn.create_stack(
        StackName=control_stack_name,
        TemplateBody=_template(control_name, control_stack_name),
        Tags=[{"Key": "sim2real", "Value": control_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, control_id))
    status = _wait_stack(cfn, control_id, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}, expected CREATE_COMPLETE"
    assert len(_applications_named(osc, control_name)) == 1, (
        f"control application {control_name!r} was not created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
