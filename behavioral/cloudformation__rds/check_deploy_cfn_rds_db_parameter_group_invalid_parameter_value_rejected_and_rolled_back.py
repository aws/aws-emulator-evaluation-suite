"""deploy-cfn-rds-db-parameter-group-invalid-parameter-value-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-db-parameter-group-invalid-parameter-value-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_FAMILY = "mysql8.0"
_PARAM_NAME = "binlog_row_image"
_UNKNOWN_VALUE = "fully"
_VALID_VALUE = "full"
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    paginator = cf.get_paginator("describe_stack_events")
    for page in paginator.paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    return rows[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def handler_reason(reason):
    """``(message, HandlerErrorCode)`` of a registry-handler failure reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return m["message"], m["code"]


def _template(name: str, value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamGroup": {
                "Type": "AWS::RDS::DBParameterGroup",
                "Properties": {
                    "DBParameterGroupName": name,
                    "Family": _FAMILY,
                    "Description": "sim2real behavioral check",
                    "Parameters": {_PARAM_NAME: value},
                },
            },
        },
        "Outputs": {
            "ParamGroupNameOut": {"Value": {"Ref": "ParamGroup"}},
        },
    })


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


_REJECTED = (
    f"Invalid parameter value: {_UNKNOWN_VALUE} for: {_PARAM_NAME} allowed values are: "
    "full,minimal,noblob (Service: Rds, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]+")
_ATTEMPT_COUNT = re.compile(r"SDK Attempt Count: \d+")


def _masked(message: str) -> str:
    message = _REQUEST_ID.sub("Request ID: <id>", message)
    return _ATTEMPT_COUNT.sub("SDK Attempt Count: <n>", message)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::RDS::DBParameterGroup declaring a binlog_row_image value outside its allowed set
    fails with RDS's exact message and the rollback leaves no group in RDS; the allowed value
    right next to it deploys and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbparametergroup.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")

    bad_name = ctx.unique_name("sim2real-cfnrds-badvalpg-")
    bad_stack_name = ctx.unique_name("sim2real-cfnrds-badvalstk-")
    bad_id = cf.create_stack(StackName=bad_stack_name, TemplateBody=_template(bad_name, _UNKNOWN_VALUE),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: delete_stack(cf, bad_id))

    bad_status = wait_stack(cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"invalid value stack settled at {bad_status!r}, expected ROLLBACK_COMPLETE"
    )
    message, code = handler_reason(failed_reason(stack_events(cf, bad_id), "ParamGroup"))
    got = (_masked(message), code)
    assert got == _REJECTED, f"the ParamGroup CREATE_FAILED reason was {got!r}, expected {_REJECTED!r}"
    bad_err = _error(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=bad_name))
    expected_bad_err = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {bad_name}")
    assert bad_err == expected_bad_err, (
        f"a group survived the rollback: describe gave {bad_err!r}, expected {expected_bad_err!r}"
    )
    delete_stack(cf, bad_id)

    # Positive control: the allowed value right next to it deploys cleanly.
    good_name = ctx.unique_name("sim2real-cfnrds-goodvalpg-")
    good_stack_name = ctx.unique_name("sim2real-cfnrds-goodvalstk-")
    good_id = cf.create_stack(StackName=good_stack_name, TemplateBody=_template(good_name, _VALID_VALUE),
                              Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: delete_stack(cf, good_id))

    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", f"control stack settled at {good_status!r}"
    param = _describe_parameter(rds, good_name, _PARAM_NAME)
    assert param is not None, f"{_PARAM_NAME} is not listed with Source='user' for the control group"
    assert param["ParameterValue"] == _VALID_VALUE, (
        f"control stored value was {param['ParameterValue']!r}, expected {_VALID_VALUE!r}"
    )

    delete_stack(cf, good_id)
    good_err = _error(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=good_name))
    expected_good_err = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {good_name}")
    assert good_err == expected_good_err, (
        f"describe after control delete gave {good_err!r}, expected {expected_good_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
