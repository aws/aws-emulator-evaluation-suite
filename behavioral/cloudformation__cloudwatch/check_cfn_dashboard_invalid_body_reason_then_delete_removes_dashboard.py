"""cfn-dashboard-invalid-body-reason-then-delete-removes-dashboard."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-dashboard-invalid-body-reason-then-delete-removes-dashboard"
GROUP = "deploy_validation"
SERVICES = ["cloudformation", "cloudwatch"]


def _board_template(name: str, body: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Board": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {"DashboardName": name, "DashboardBody": body},
            },
        },
    })


def _poll_until_terminal(cf, stack_id: str, *, budget_s: float = 180.0) -> str:
    """DescribeStacks by stack id (survives past delete) until a status ending COMPLETE/FAILED."""
    deadline = time.monotonic() + budget_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            return status
        time.sleep(4)
    raise AssertionError(f"stack {stack_id!r} still {status!r} after {budget_s}s")


def _board_create_failed_events(cf, stack_id: str) -> list:
    return [
        e for e in cf.describe_stack_events(StackName=stack_id)["StackEvents"]
        if e.get("LogicalResourceId") == "Board" and e.get("ResourceStatus") == "CREATE_FAILED"
    ]


def _handler_reason(request_id: str, request_token: str) -> str:
    """The CloudWatch Dashboard handler's CREATE_FAILED reason for a non-JSON DashboardBody."""
    return (
        'Resource handler returned message: "The field DashboardBody must be a valid JSON '
        f'object (Service: CloudWatch, Status Code: 400, Request ID: {request_id}) '
        '(SDK Attempt Count: 1)" '
        f'(RequestToken: {request_token}, HandlerErrorCode: InvalidRequest)'
    )


def _split_reason_ids(reason: str) -> tuple[str, str]:
    """Pull the per-call Request ID and RequestToken out of a CREATE_FAILED reason."""
    head, _, tail = reason.partition("Request ID: ")
    assert tail, f"reason {reason!r} carries no 'Request ID: ' marker"
    request_id, _, tail = tail.partition(")")
    head, _, tail = tail.partition("RequestToken: ")
    assert tail, f"reason {reason!r} carries no 'RequestToken: ' marker"
    request_token, _, _ = tail.partition(",")
    return request_id, request_token


def _dashboard_body_or_absent(cw, name: str):
    """GetDashboard's parsed body, or raises on an unexpected success past a confirmed absence."""
    try:
        resp = cw.get_dashboard(DashboardName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ResourceNotFound", (
            f"GetDashboard({name!r}) raised {err['Code']!r}, expected ResourceNotFound"
        )
        want = f"Dashboard {name} does not exist"
        assert err["Message"] == want, (
            f"GetDashboard({name!r}) absence said {err['Message']!r}, expected {want!r}"
        )
        return None
    return json.loads(resp["DashboardBody"])


def _delete_stack_by_name_if_present(cf, stack_name: str) -> None:
    try:
        cf.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cf.delete_stack(StackName=stack_name)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-JSON DashboardBody fails CREATE with the handler's exact field-validation reason,
    rolls the stack back, and GetDashboard reports the dashboard absent by name; a valid body
    deploys, round-trips through GetDashboard, and deleting the stack removes it.
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-cfndash-")
    dash_name = ctx.unique_name("sim2real-cfndash-board-")
    ctx.on_cleanup(lambda: _delete_stack_by_name_if_present(cf, stack_name))

    # ---- a non-JSON body fails the resource with its exact handler reason, and rolls back ----
    bad = cf.create_stack(StackName=stack_name, TemplateBody=_board_template(dash_name, "{not json"))
    bad_id = bad["StackId"]
    status = _poll_until_terminal(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack status after the non-JSON create is {status!r}, expected ROLLBACK_COMPLETE"
    )

    failures = _board_create_failed_events(cf, bad_id)
    assert len(failures) == 1, f"expected exactly one CREATE_FAILED event for Board, got {len(failures)}"
    reason = failures[0].get("ResourceStatusReason", "")
    request_id, request_token = _split_reason_ids(reason)
    want_reason = _handler_reason(request_id, request_token)
    assert reason == want_reason, f"CREATE_FAILED reason was {reason!r}, expected {want_reason!r}"

    assert _dashboard_body_or_absent(cw, dash_name) is None, (
        f"GetDashboard({dash_name!r}) returned a body despite the rolled-back create"
    )

    # ---- the name is free again once the rolled-back stack is deleted ----
    cf.delete_stack(StackName=bad_id)
    status = _poll_until_terminal(cf, bad_id)
    assert status == "DELETE_COMPLETE", (
        f"deleting the rolled-back stack ended at {status!r}, expected DELETE_COMPLETE"
    )

    # ---- a valid body deploys and round-trips through GetDashboard ----
    good_body = {"widgets": [{"type": "text", "properties": {"markdown": "steady"}}]}
    good = cf.create_stack(
        StackName=stack_name, TemplateBody=_board_template(dash_name, json.dumps(good_body))
    )
    good_id = good["StackId"]
    status = _poll_until_terminal(cf, good_id)
    assert status == "CREATE_COMPLETE", f"stack status with a valid body is {status!r}, expected CREATE_COMPLETE"

    deployed = _dashboard_body_or_absent(cw, dash_name)
    assert deployed == good_body, f"GetDashboard({dash_name!r}) returned {deployed!r}, expected {good_body!r}"

    # ---- deleting the stack removes the dashboard it deployed ----
    cf.delete_stack(StackName=good_id)
    status = _poll_until_terminal(cf, good_id)
    assert status == "DELETE_COMPLETE", (
        f"deleting the deployed stack ended at {status!r}, expected DELETE_COMPLETE"
    )
    assert _dashboard_body_or_absent(cw, dash_name) is None, (
        f"GetDashboard({dash_name!r}) still returns a body after the stack that created it was deleted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
