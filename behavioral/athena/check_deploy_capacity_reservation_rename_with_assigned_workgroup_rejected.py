"""deploy-capacity-reservation-rename-with-assigned-workgroup-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-capacity-reservation-rename-with-assigned-workgroup-rejected"
GROUP = "deploy"
SERVICES = ["athena"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})

_HANDLER_WRAPPER = re.compile(
    r'^Resource handler returned message: "(?P<msg>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _template(reservation_name: str, wg_name: str, *, assigned: bool = True) -> str:
    cap_res_props: dict = {"Name": reservation_name, "TargetDpus": 4}
    if assigned:
        cap_res_props["CapacityAssignmentConfiguration"] = {
            "CapacityAssignments": [{"WorkgroupNames": [{"Ref": "WG"}]}]
        }
    return json.dumps({
        "Resources": {
            "WG": {"Type": "AWS::Athena::WorkGroup", "Properties": {"Name": wg_name}},
            "CapRes": {"Type": "AWS::Athena::CapacityReservation", "Properties": cap_res_props},
        },
    })


def _wait_stack(cfn, stack_name: str, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {stack_name} does not exist"
            ):
                return "DELETE_COMPLETE"
            raise
        if status in _STACK_TERMINAL:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")


def _stack_events(cfn, stack_name: str) -> list:
    events = []
    token = None
    while True:
        kwargs = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            return list(reversed(events))


def _failed_reason(events: list, logical_id: str) -> str:
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"].endswith("_FAILED")]
    assert len(rows) == 1, f"expected exactly one failed row for {logical_id!r}, got {rows!r}"
    return rows[0]


def _handler_failure(reason: str) -> tuple[str, str]:
    """``(message with its Request ID redacted, HandlerErrorCode)`` of a resource-handler reason."""
    match = _HANDLER_WRAPPER.match(reason or "")
    assert match is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <redacted>", match["msg"])
    return message, match["code"]


def _safe_delete_stack(cfn, stack_name: str) -> None:
    """Teardown safety net: a no-op if the body's own delete already removed the stack."""
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError", f"Stack with id {stack_name} does not exist"
        ):
            return
        raise
    _wait_stack(cfn, stack_name)


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to fail, but it succeeded: {result!r}")


def _list_all_reservation_names(athena) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_capacity_reservations(**kwargs)
        names.extend(r["Name"] for r in resp.get("CapacityReservations", []))
        token = resp.get("NextToken")
        if not token:
            return names


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Renaming an AWS::Athena::CapacityReservation that still carries a workgroup assignment
    rolls the stack update back, because the replacement cannot claim a workgroup its
    predecessor still holds; the original reservation is left exactly as it was."""
    athena = ctx.client("athena")
    cfn = ctx.client("cloudformation")

    wg_name = ctx.unique_name("sim2real-behav-capres-wg-")
    name_a = ctx.unique_name("sim2real-behav-capres-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name_a, wg_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}"

    created = athena.get_capacity_reservation(Name=name_a)["CapacityReservation"]
    got = (created["Status"], created["TargetDpus"], created["AllocatedDpus"])
    assert got == ("ACTIVE", 4, 4), f"expected (ACTIVE, 4, 4) after the CFN create, got {got!r}"

    # Rename while the assignment is still in the template: the replacement reservation
    # cannot claim a workgroup the still-live original holds, so the update rolls back.
    name_b = ctx.unique_name("sim2real-behav-capres-")
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(name_b, wg_name))
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rename-while-assigned update ended {status!r}"

    events = _stack_events(cfn, stack_name)
    reason = _failed_reason(events, "CapRes")
    message, code = _handler_failure(reason)
    expected_message = (
        "One or more workgroups are assigned to another active reservation. Update your "
        "reservation assignments to continue. (Service: Athena, Status Code: 400, "
        "Request ID: <redacted>) (SDK Attempt Count: 1)"
    )
    assert (message, code) == (expected_message, "InvalidRequest"), (
        f"expected {(expected_message, 'InvalidRequest')!r}, got {(message, code)!r}"
    )

    # The original reservation is untouched: still the live one under name_a.
    live = athena.get_capacity_reservation(Name=name_a)["CapacityReservation"]
    assert (live["Status"], live["TargetDpus"]) == ("ACTIVE", 4), (
        f"expected the rolled-back stack to leave (ACTIVE, 4) under {name_a!r}, got "
        f"{(live['Status'], live['TargetDpus'])!r}"
    )
    names = _list_all_reservation_names(athena)
    assert name_a in names, f"{name_a!r} missing after the rollback: {sorted(names)!r}"
    assert name_b not in names, f"{name_b!r} must not exist after the rollback: {sorted(names)!r}"

    # Positive control: the identical rename succeeds once the template drops the
    # assignment, so the replacement has no workgroup left to contest.
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(name_b, wg_name, assigned=False))
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"control rename (no assignment) ended {status!r}"
    replaced = athena.get_capacity_reservation(Name=name_b)["CapacityReservation"]
    assert (replaced["Status"], replaced["TargetDpus"]) == ("ACTIVE", 4), (
        f"expected the control rename to land (ACTIVE, 4) under {name_b!r}, got "
        f"{(replaced['Status'], replaced['TargetDpus'])!r}"
    )
    old_code, old_message = _error(lambda: athena.get_capacity_reservation(Name=name_a))
    expected_old = ("InvalidRequestException", f"Reservation with name {name_a} not found.")
    assert (old_code, old_message) == expected_old, (
        f"expected the replaced reservation {name_a!r} to read not-found with {expected_old!r}, "
        f"got {(old_code, old_message)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
