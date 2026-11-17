"""deploy-opensearch-application-update-in-place-and-replacement."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-opensearch-application-update-in-place-and-replacement"
GROUP = "deploy"
SERVICES = ["cloudformation", "opensearch"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_NOT_FOUND = ("ResourceNotFoundException", "Application does not exist")


def _wait_stack(cfn, stack_id: str, timeout_s: float = 300.0, interval_s: float = 3.0) -> str:
    """Poll DescribeStacks by StackId until the status leaves an IN_PROGRESS state; return it.

    StackId (not StackName) stays describable once DELETE_COMPLETE, so a delete's own wait does
    not race the moment the name stops resolving.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id!r} still {status!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE, idempotent if already gone."""
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status not in _TERMINAL:
        status = _wait_stack(cfn, stack_id, timeout_s=900.0)
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(cfn, stack_id, timeout_s=300.0)
    assert final == "DELETE_COMPLETE", f"stack {stack_id!r} delete ended {final!r}"


def _stack_outputs(cfn, stack_id: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _failure_reasons(cfn, stack_id: str) -> list[tuple[str, str, str]]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason)`` for every *_FAILED event."""
    events = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason", ""))
        for page in events for e in page["StackEvents"]
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _expect_not_found(fn) -> None:
    """Assert ``fn()`` raises exactly the application-gone error."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {got!r}"
        return
    raise AssertionError(f"expected the application to be gone, but the call returned {result!r}")


def _application_names(osc) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = osc.list_applications(**kwargs)
        names.update(s["name"] for s in page["ApplicationSummaries"])
        token = page.get("nextToken")
        if not token:
            return names


def _template(app_name: str, admin_value: str, tag_value: str) -> str:
    return f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  App:
    Type: AWS::OpenSearchService::Application
    Properties:
      Name: {app_name}
      AppConfigs:
        - Key: opensearchDashboards.dashboardAdmin.users
          Value: {admin_value}
      DataSources: []
      Tags:
        - Key: sim2real
          Value: {tag_value}
Outputs:
  AppId:
    Value: !GetAtt App.Id
  AppArn:
    Value: !GetAtt App.Arn
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::OpenSearchService::Application updates its AppConfigs in place,
    keeping the same application, and replaces the application when its Name changes; the
    replaced application is gone and the final stack delete leaves no application behind.
    """
    cfn = ctx.client("cloudformation")
    osc = ctx.client("opensearch")

    stack_name = ctx.unique_name("sim2real-osapp-stack-")
    name_1 = ctx.unique_name("sim2real-osapp-")
    name_2 = ctx.unique_name("sim2real-osapp2-")
    admin_1 = ctx.unique_name("sim2real-admin-")
    admin_2 = ctx.unique_name("sim2real-admin-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name_1, admin_1, stack_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack creation ended {status!r}, expected CREATE_COMPLETE"

    outputs = _stack_outputs(cfn, stack_id)
    id_1, arn_1 = outputs["AppId"], outputs["AppArn"]
    app = osc.get_application(id=id_1)
    got = (app["name"], app["arn"], app["status"], app["appConfigs"])
    want = (name_1, arn_1, "ACTIVE", [{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_1}])
    assert got == want, f"GetApplication after create returned {got!r}, expected {want!r}"
    app_tags = {t["Key"]: t["Value"] for t in osc.list_tags(ARN=arn_1)["TagList"]
                if not t["Key"].startswith("aws:")}
    assert app_tags == {"sim2real": stack_name}, f"tags after create: {app_tags!r}"
    assert name_1 in _application_names(osc), f"{name_1!r} missing from ListApplications after create"

    # AppConfigs updates with no interruption: the same application keeps its Id and Arn.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(name_1, admin_2, stack_name))
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"in-place update ended {status!r}, expected UPDATE_COMPLETE; "
        f"failures: {_failure_reasons(cfn, stack_id)!r}"
    )

    outputs = _stack_outputs(cfn, stack_id)
    assert (outputs["AppId"], outputs["AppArn"]) == (id_1, arn_1), (
        f"an AppConfigs-only update changed the identity to {outputs!r}, expected the same {(id_1, arn_1)!r}"
    )
    app = osc.get_application(id=id_1)
    got = (app["name"], app["arn"], app["appConfigs"])
    want = (name_1, arn_1, [{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_2}])
    assert got == want, f"GetApplication after in-place update returned {got!r}, expected {want!r}"

    # Name requires replacement: a new application, the old one gone.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(name_2, admin_2, stack_name))
    status = _wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "UPDATE_COMPLETE", (
        f"replacing update ended {status!r}, expected UPDATE_COMPLETE; "
        f"failures: {_failure_reasons(cfn, stack_id)!r}"
    )

    outputs = _stack_outputs(cfn, stack_id)
    id_2, arn_2 = outputs["AppId"], outputs["AppArn"]
    assert id_2 != id_1, f"a Name change kept the same AppId {id_2!r}; expected a new application"

    app = osc.get_application(id=id_2)
    got = (app["name"], app["arn"], app["appConfigs"])
    want = (name_2, arn_2, [{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_2}])
    assert got == want, f"GetApplication for the replacement returned {got!r}, expected {want!r}"
    names = _application_names(osc)
    assert name_2 in names and name_1 not in names, (
        f"ListApplications after replacement: {sorted(names)!r}, expected {name_2!r} present and {name_1!r} gone"
    )

    _expect_not_found(lambda: osc.get_application(id=id_1))
    _expect_not_found(lambda: osc.update_application(
        id=id_1, appConfigs=[{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_1}]
    ))

    _delete_stack(cfn, stack_id)
    _expect_not_found(lambda: osc.get_application(id=id_2))
    assert name_2 not in _application_names(osc), f"{name_2!r} still in ListApplications after the stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
