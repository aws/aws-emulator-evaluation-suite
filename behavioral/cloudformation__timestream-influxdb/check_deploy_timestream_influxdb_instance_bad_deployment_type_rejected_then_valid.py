"""deploy-timestream-influxdb-instance-bad-deployment-type-rejected-then-valid."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-timestream-influxdb-instance-bad-deployment-type-rejected-then-valid"
GROUP = "deploy"
SERVICES = ["cloudformation", "timestream-influxdb"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

# An InfluxDB instance takes many minutes to reach AVAILABLE on AWS; the bound leaves the suite
# budget room for the rejected stack and the rest of the body.
_CREATE_TIMEOUT_S = 1020.0
# The stack delete waits on the instance delete; the poll after it is a short convergence read.
_GONE_TIMEOUT_S = 120.0
_GONE = ("ResourceNotFoundException", "The DB instance with db id does not exist")


def _template(name, username, subnet_id, sg_id, deployment_type="SINGLE_AZ"):
    """The instance template; the per-run password arrives as a NoEcho parameter."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Password": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "DbInstance": {
                "Type": "AWS::Timestream::InfluxDBInstance",
                "Properties": {
                    "Name": name,
                    "DbInstanceType": "db.influx.medium",
                    "AllocatedStorage": 20,
                    "DbStorageType": "InfluxIOIncludedT1",
                    "Username": username,
                    "Password": {"Ref": "Password"},
                    "VpcSubnetIds": [subnet_id],
                    "VpcSecurityGroupIds": [sg_id],
                    "PubliclyAccessible": False,
                    "DeploymentType": deployment_type,
                    "Tags": [{"Key": "sim2real-resource", "Value": name}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "DbInstance"}},
            "InstanceArn": {"Value": {"Fn::GetAtt": ["DbInstance", "Arn"]}},
            "InstanceEndpoint": {"Value": {"Fn::GetAtt": ["DbInstance", "Endpoint"]}},
            "InstanceSecretArn": {
                "Value": {"Fn::GetAtt": ["DbInstance", "InfluxAuthParametersSecretArn"]}
            },
        },
    })


def _password():
    """Per-run key material, passed only as a NoEcho parameter."""
    return [{"ParameterKey": "Password", "ParameterValue": secrets.token_hex(12)}]


def _listed(influx, name):
    return [i["id"] for i in paginate(influx, "list_db_instances", "items") if i["name"] == name]


def _instance_teardown(cfn, influx, stack_id, instance_id):
    """A cleanup deleting the control stack, then proving its instance gone within a bound."""

    def run_teardown() -> None:
        delete_stack(cfn, stack_id)
        until_raises(lambda: influx.get_db_instance(identifier=instance_id),
                     timeout_s=_GONE_TIMEOUT_S)
        expect_error(lambda: influx.get_db_instance(identifier=instance_id), *_GONE)

    return run_teardown


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation InfluxDB instance with an invalid DeploymentType fails early validation.

    No instance of that name is listed, while the same template with SINGLE_AZ deploys; only the
    control pays the slow instance create.
    """
    net = ctx.network()
    influx = ctx.client("timestream-influxdb")
    cfn = ctx.client("cloudformation")
    subnet_id, sg_id = net.subnet_ids[0], net.security_group_id
    username = "sim2realuser" + secrets.token_hex(3)

    bad_name = ctx.unique_name("sim2real-cfntsinfxbad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfntsinfxbadstk-"),
                          _template(bad_name, username, subnet_id, sg_id, "MULTI_AZ_BOGUS"),
                          Parameters=_password())
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    want_rows = [(
        "DbInstance", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "MULTI_AZ_BOGUS is not a valid enum value. Supported values: "
        "[SINGLE_AZ, WITH_MULTIAZ_STANDBY]",
        "/Resources/DbInstance/Properties/DeploymentType",
    )]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"
    # Rollback absence through Timestream for InfluxDB, by name, before any delete.
    assert _listed(influx, bad_name) == [], f"the rejected template's instance {bad_name!r} exists"
    delete_stack(cfn, bad_id)

    # Positive control: the same template with the one property given a VALID value.
    good_name = ctx.unique_name("sim2real-cfntsinfxgood-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfntsinfxgoodstk-"),
                           _template(good_name, username, subnet_id, sg_id, "SINGLE_AZ"),
                           Parameters=_password())
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    instance_id = stack_outputs(cfn, good_id)["InstanceId"]
    # Runs before create_stack's own delete (LIFO), so the instance's delete is seen to finish.
    ctx.on_cleanup(_instance_teardown(cfn, influx, good_id, instance_id))
    assert _listed(influx, good_name) == [instance_id], "the control instance is not listed"
    control = influx.get_db_instance(identifier=instance_id)
    got = (control["status"], control["deploymentType"], control["name"])
    assert got == ("AVAILABLE", "SINGLE_AZ", good_name), f"control instance reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
