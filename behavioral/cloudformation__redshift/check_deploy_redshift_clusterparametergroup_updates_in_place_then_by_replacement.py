"""deploy-redshift-clusterparametergroup-updates-in-place-then-by-replacement."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshift-clusterparametergroup-updates-in-place-then-by-replacement"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 300.0
_FAMILY = "redshift-2.0"
_DESCRIPTION = "sim2real behavioral cluster parameter group for an update lifecycle"


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _stack_events(cf, stack_id):
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events[::-1]


def _failure_reasons(cf, stack_id):
    return [f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in _stack_events(cf, stack_id) if e["ResourceStatus"].endswith("FAILED")]


def _delete_stack(cf, stack_id):
    """Delete by StackId; raise unless it ends DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _wait_stack(cf, stack_id, _TERMINAL, _DELETE_BUDGET_S)
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: "
                             f"{_failure_reasons(cf, stack_id)!r}")


def _physical_id(cf, stack_id, logical_id):
    """The current PhysicalResourceId CloudFormation holds for ``logical_id``."""
    return cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _expect_not_found(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(pg_name: str, timeout_value: str) -> str:
    """A ClusterParameterGroup whose name and one Parameter value are both template-driven."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamGroup": {
                "Type": "AWS::Redshift::ClusterParameterGroup",
                "Properties": {
                    "ParameterGroupName": pg_name,
                    "Description": _DESCRIPTION,
                    "ParameterGroupFamily": _FAMILY,
                    "Parameters": [
                        {"ParameterName": "statement_timeout", "ParameterValue": timeout_value},
                    ],
                },
            },
        },
        "Outputs": {"ParamGroupRef": {"Value": {"Ref": "ParamGroup"}}},
    })


def _statement_timeout(rs, pg_name: str) -> tuple:
    """(ParameterValue, Source) of ``statement_timeout`` on ``pg_name``."""
    pages = rs.get_paginator("describe_cluster_parameters").paginate(ParameterGroupName=pg_name)
    params = {p["ParameterName"]: p for page in pages for p in page["Parameters"]}
    found = params["statement_timeout"]
    return found["ParameterValue"], found["Source"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Redshift ClusterParameterGroup's Parameters update in place while its
    name stays bound to the same physical resource, a ParameterGroupName change replaces it
    instead, and deleting the stack removes whichever group is current.
    """
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift")

    stack = ctx.unique_name("sim2real-cfnrs-pgupd-")
    pg_name1 = ctx.unique_name("sim2real-cfnrs-pg1-")
    pg_name2 = ctx.unique_name("sim2real-cfnrs-pg2-")

    stack_id = cfn.create_stack(StackName=stack, TemplateBody=_template(pg_name1, "5000"))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack} ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )

    physical_1 = _physical_id(cfn, stack_id, "ParamGroup")
    assert physical_1 == pg_name1, f"ParamGroup physical id {physical_1!r}, expected {pg_name1!r}"
    groups = rs.describe_cluster_parameter_groups(ParameterGroupName=pg_name1)["ParameterGroups"]
    got_group = [(g["ParameterGroupName"], g["ParameterGroupFamily"], g["Description"])
                for g in groups]
    assert got_group == [(pg_name1, _FAMILY, _DESCRIPTION)], f"created group read {got_group!r}"
    assert _statement_timeout(rs, pg_name1) == ("5000", "user"), (
        f"statement_timeout after create: {_statement_timeout(rs, pg_name1)!r}"
    )

    # Changing only the Parameter value is an in-place update: no createOnly property moved.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(pg_name1, "7000"))
    status = _wait_stack(cfn, stack_id, timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", (
        f"in-place update ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    physical_2 = _physical_id(cfn, stack_id, "ParamGroup")
    assert physical_2 == physical_1, (
        f"ParamGroup physical id changed to {physical_2!r} on a Parameters-only update"
    )
    assert _statement_timeout(rs, pg_name1) == ("7000", "user"), (
        f"statement_timeout after the in-place update: {_statement_timeout(rs, pg_name1)!r}"
    )

    # Changing ParameterGroupName moves a createOnly property, which CloudFormation can only
    # satisfy by replacement: a new group is created and the old one is deleted.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(pg_name2, "7000"))
    status = _wait_stack(cfn, stack_id, timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", (
        f"replacing update ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    physical_3 = _physical_id(cfn, stack_id, "ParamGroup")
    assert physical_3 == pg_name2 != physical_1, (
        f"ParamGroup physical id {physical_3!r}, expected the new name {pg_name2!r}"
    )
    got_group = [(g["ParameterGroupName"], g["ParameterGroupFamily"], g["Description"])
                for g in rs.describe_cluster_parameter_groups(
                    ParameterGroupName=pg_name2)["ParameterGroups"]]
    assert got_group == [(pg_name2, _FAMILY, _DESCRIPTION)], f"replacement group read {got_group!r}"
    assert _statement_timeout(rs, pg_name2) == ("7000", "user"), (
        f"statement_timeout on the replacement group: {_statement_timeout(rs, pg_name2)!r}"
    )
    _expect_not_found(
        lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=pg_name1),
        "ClusterParameterGroupNotFound", f"ClusterParameterGroup {pg_name1} not found.",
    )

    _delete_stack(cfn, stack_id)
    _expect_not_found(
        lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=pg_name2),
        "ClusterParameterGroupNotFound", f"ClusterParameterGroup {pg_name2} not found.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
