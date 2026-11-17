"""deploy-cfn-rds-db-parameter-group-binlog-row-image-casing-preserved."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-db-parameter-group-binlog-row-image-casing-preserved"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_FAMILY = "mysql8.0"
_PARAM_NAME = "binlog_row_image"
_PARAM_VALUE = "FULL"


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id, timeout_s=300.0):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _template(name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ParamGroup": {
                    "Type": "AWS::RDS::DBParameterGroup",
                    "Properties": {
                        "DBParameterGroupName": name,
                        "Family": _FAMILY,
                        "Description": "sim2real behavioral check",
                        "Parameters": {_PARAM_NAME: _PARAM_VALUE},
                    },
                },
            },
            "Outputs": {
                "ParamGroupNameOut": {"Value": {"Ref": "ParamGroup"}},
            },
        }
    )


def _describe_parameter(rds, pg_name: str, param_name: str):
    paginator = rds.get_paginator("describe_db_parameters")
    for page in paginator.paginate(DBParameterGroupName=pg_name, Source="user"):
        for p in page["Parameters"]:
            if p["ParameterName"] == param_name:
                return p
    return None


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; AssertionError on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::RDS::DBParameterGroup declaring Parameters: {binlog_row_image: FULL} through
    CloudFormation reaches CREATE_COMPLETE, and RDS stores the parameter with that exact casing.
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")

    pg_name = ctx.unique_name("sim2real-cfnrds-binlogpg-")
    stack_name = ctx.unique_name("sim2real-cfnrds-binlogstk-")

    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=_template(pg_name),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: delete_stack(cf, stack_id))

    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack settled at {status!r}, expected CREATE_COMPLETE"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    }
    assert outputs["ParamGroupNameOut"] == pg_name, (
        f"the stack's Ref was {outputs['ParamGroupNameOut']!r}, expected {pg_name!r}"
    )

    param = _describe_parameter(rds, pg_name, _PARAM_NAME)
    assert param is not None, f"{_PARAM_NAME} is not listed with Source='user' after the deploy"
    assert param["ParameterValue"] == _PARAM_VALUE, (
        f"stored value was {param['ParameterValue']!r}, expected {_PARAM_VALUE!r}"
    )

    delete_stack(cf, stack_id)
    code, message = _error(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=pg_name))
    expected = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {pg_name}")
    assert (code, message) == expected, (
        f"describe after stack delete gave {(code, message)!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
