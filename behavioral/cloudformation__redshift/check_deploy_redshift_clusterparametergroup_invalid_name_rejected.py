"""deploy-redshift-clusterparametergroup-invalid-name-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshift-clusterparametergroup-invalid-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_DELETE_BUDGET_S = 300.0
_FAMILY = "redshift-2.0"
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def _delete_stack_if_present(cf, stack_id):
    """Delete ``stack_id`` unless it is already gone."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _stack_events(cf, stack_id):
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events[::-1]


def _failed_reason(cf, stack_id, logical_id):
    """The single CREATE_FAILED row's reason for ``logical_id``."""
    rows = [e.get("ResourceStatusReason") for e in _stack_events(cf, stack_id)
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _masked_handler_reason(reason: str, account: str, *names: str) -> tuple:
    """``(message, HandlerErrorCode)`` of a registry-handler failure, request id/token masked."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    text = m["message"]
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text, m["code"]


def _expect_not_found(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(pg_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamGroup": {
                "Type": "AWS::Redshift::ClusterParameterGroup",
                "Properties": {
                    "ParameterGroupName": pg_name,
                    "Description": "sim2real behavioral cluster parameter group",
                    "ParameterGroupFamily": _FAMILY,
                    "Parameters": [
                        {"ParameterName": "statement_timeout", "ParameterValue": "5000"},
                    ],
                },
            },
        },
        "Outputs": {"ParamGroupRef": {"Value": {"Ref": "ParamGroup"}}},
    })


_BAD_NAME = "Sim2Real_Invalid_Name"
_INVALID_IDENTIFIER = (
    "The parameter DBParameterGroupName is not a valid identifier. Identifiers must begin "
    "with a letter; must contain only ASCII letters, digits, and hyphens; and must not end "
    "with a hyphen or contain two consecutive hyphens."
)
_REJECTED = (
    f"{_INVALID_IDENTIFIER} (Service: Redshift, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "GeneralServiceException",
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Redshift ClusterParameterGroup whose name holds characters Redshift
    rejects (upper case, underscores) creates no parameter group, while the same template with
    a valid name deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift")
    good_pg_name = ctx.unique_name("sim2real-cfnrs-okname-")

    bad_stack = ctx.unique_name("sim2real-cfnrs-badname-stack-")
    bad_id = cfn.create_stack(StackName=bad_stack, TemplateBody=_template(_BAD_NAME))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, bad_id))
    status = _wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = _masked_handler_reason(_failed_reason(cfn, bad_id, "ParamGroup"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # The same identifier rule applies to a direct read: nothing by that name was ever created.
    _expect_not_found(
        lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=_BAD_NAME),
        "InvalidParameterValue", _INVALID_IDENTIFIER,
    )

    good_stack = ctx.unique_name("sim2real-cfnrs-okname-stack-")
    good_id = cfn.create_stack(StackName=good_stack, TemplateBody=_template(good_pg_name))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, good_id))
    status = _wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    pages = rs.get_paginator("describe_cluster_parameters").paginate(
        ParameterGroupName=good_pg_name
    )
    params = {p["ParameterName"]: p for page in pages for p in page["Parameters"]}
    got_param = (params["statement_timeout"]["ParameterValue"], params["statement_timeout"]["Source"])
    assert got_param == ("5000", "user"), f"control group's statement_timeout reads {got_param!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
