"""deploy-capacity-reservation-cloudformation-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-capacity-reservation-cloudformation-lifecycle"
GROUP = "deploy"
SERVICES = ["athena"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})


def _template(reservation_name: str, target_dpus: int, wg_name: str, *, assigned: bool = True) -> str:
    cap_res_props: dict = {"Name": reservation_name, "TargetDpus": target_dpus}
    if assigned:
        cap_res_props["CapacityAssignmentConfiguration"] = {
            "CapacityAssignments": [{"WorkgroupNames": [{"Ref": "WG"}]}]
        }
    return json.dumps({
        "Resources": {
            "WG": {"Type": "AWS::Athena::WorkGroup", "Properties": {"Name": wg_name}},
            "CapRes": {
                "Type": "AWS::Athena::CapacityReservation",
                "Properties": cap_res_props,
            },
        },
        "Outputs": {"ReservationArn": {"Value": {"Ref": "CapRes"}}},
    })


def _wait_stack(cfn, stack_name: str, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            # A delete can finish fast enough that the by-name lookup already reports the
            # stack gone instead of a last DELETE_COMPLETE row.
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {stack_name} does not exist"
            ):
                return "DELETE_COMPLETE"
            raise
        if status in _STACK_TERMINAL:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")


def _stack_output(cfn, stack_name: str, key: str) -> str:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert key in outputs, f"stack {stack_name} carries no output {key!r}: {outputs!r}"
    return outputs[key]


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    status = _wait_stack(cfn, stack_name)
    assert status == "DELETE_COMPLETE", f"stack {stack_name} delete ended {status!r}"


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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed capacity reservation and its workgroup assignment read back
    through the Athena API; raising TargetDpus updates it in place, renaming it replaces it,
    and the stack delete cancels and removes the surviving reservation."""
    athena = ctx.client("athena")
    cfn = ctx.client("cloudformation")

    wg_name = ctx.unique_name("sim2real-behav-capres-wg-")
    name_a = ctx.unique_name("sim2real-behav-capres-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name_a, 4, wg_name),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}"

    arn_a = _stack_output(cfn, stack_name, "ReservationArn")
    expected_arn_a = f"arn:aws:athena:{ctx.region}:{ctx.account}:capacity-reservation/{name_a}"
    assert arn_a == expected_arn_a, f"expected reservation ARN {expected_arn_a!r}, got {arn_a!r}"

    res = athena.get_capacity_reservation(Name=name_a)["CapacityReservation"]
    got = (res["Status"], res["TargetDpus"], res["AllocatedDpus"])
    assert got == ("ACTIVE", 4, 4), f"expected (ACTIVE, 4, 4) after the CFN create, got {got!r}"
    assignments = athena.get_capacity_assignment_configuration(CapacityReservationName=name_a)[
        "CapacityAssignmentConfiguration"
    ]["CapacityAssignments"]
    assert assignments == [{"WorkGroupNames": [wg_name]}], (
        f"expected the template's single assignment to {wg_name!r}, got {assignments!r}"
    )

    # TargetDpus is not a CFN createOnly property, so raising it updates the reservation
    # in place: the ARN (which embeds the Name) is unchanged.
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(name_a, 8, wg_name))
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"in-place TargetDpus update ended {status!r}"
    arn_after_inplace = _stack_output(cfn, stack_name, "ReservationArn")
    assert arn_after_inplace == arn_a, (
        f"expected the unchanged reservation ARN {arn_a!r} after an in-place update, "
        f"got {arn_after_inplace!r}"
    )
    res = athena.get_capacity_reservation(Name=name_a)["CapacityReservation"]
    got = (res["Status"], res["TargetDpus"], res["AllocatedDpus"])
    assert got == ("ACTIVE", 8, 8), f"expected (ACTIVE, 8, 8) after the in-place update, got {got!r}"

    # Name is a CFN createOnly property, so renaming it replaces the reservation. The
    # replacement is created before the old one is torn down, and Athena refuses to assign
    # a workgroup already held by another active reservation, so the renamed template
    # carries no assignment: the old reservation keeps wg_name until CFN deletes it.
    name_b = ctx.unique_name("sim2real-behav-capres-")
    cfn.update_stack(
        StackName=stack_name, TemplateBody=_template(name_b, 8, wg_name, assigned=False)
    )
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"name-replacement update ended {status!r}"
    arn_b = _stack_output(cfn, stack_name, "ReservationArn")
    expected_arn_b = f"arn:aws:athena:{ctx.region}:{ctx.account}:capacity-reservation/{name_b}"
    assert arn_b == expected_arn_b, f"expected reservation ARN {expected_arn_b!r}, got {arn_b!r}"
    assert arn_b != arn_a, f"renaming must replace the reservation, but the ARN stayed {arn_b!r}"

    old_code, old_message = _error(lambda: athena.get_capacity_reservation(Name=name_a))
    expected_old = ("InvalidRequestException", f"Reservation with name {name_a} not found.")
    assert (old_code, old_message) == expected_old, (
        f"expected the replaced reservation {name_a!r} to read not-found with {expected_old!r}, "
        f"got {(old_code, old_message)!r}"
    )

    res_b = athena.get_capacity_reservation(Name=name_b)["CapacityReservation"]
    got_b = (res_b["Status"], res_b["TargetDpus"], res_b["AllocatedDpus"])
    assert got_b == ("ACTIVE", 8, 8), f"expected the replacement to read (ACTIVE, 8, 8), got {got_b!r}"
    names = _list_all_reservation_names(athena)
    assert name_a not in names, f"{name_a!r} (replaced) is still listed: {sorted(names)!r}"
    assert name_b in names, f"{name_b!r} (current) is missing from {sorted(names)!r}"

    _delete_stack(cfn, stack_name)
    final_code, final_message = _error(lambda: athena.get_capacity_reservation(Name=name_b))
    expected_final = ("InvalidRequestException", f"Reservation with name {name_b} not found.")
    assert (final_code, final_message) == expected_final, (
        f"expected the deleted reservation {name_b!r} to read not-found with {expected_final!r}, "
        f"got {(final_code, final_message)!r}"
    )
    remaining = _list_all_reservation_names(athena)
    assert name_b not in remaining, f"{name_b!r} still listed after the stack delete: {sorted(remaining)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
