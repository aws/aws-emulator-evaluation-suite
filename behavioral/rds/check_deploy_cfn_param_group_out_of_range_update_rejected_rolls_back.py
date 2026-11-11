"""deploy-cfn-param-group-out-of-range-update-rejected-rolls-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-param-group-out-of-range-update-rejected-rolls-back"
GROUP = "deploy-sql-and-replace"
SERVICES = ["rds"]

_PARAM = "innodb_lock_wait_timeout"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A stack update setting a DBParameterGroup value outside AllowedValues is refused by RDS; the
    stack ends UPDATE_ROLLBACK_COMPLETE and the parameter keeps the prior accepted update's value.
    """
    rds = ctx.client("rds")
    cfn = ctx.client("cloudformation")

    eng = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)["DBEngineVersions"]
    assert eng, "describe_db_engine_versions(mysql, DefaultOnly) returned no default version"
    family = eng[0]["DBParameterGroupFamily"]
    allowed = _allowed_values(rds, family)
    lo = int(allowed.split("-")[0])
    assert lo >= 1, f"{_PARAM} AllowedValues {allowed!r}; expected a positive lower bound"
    bad = str(lo - 1)

    stack_name = ctx.unique_name("sim2real-rds2-pg-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"LockWait": {"Type": "String"}},
        "Resources": {
            "DbParams": {
                "Type": "AWS::RDS::DBParameterGroup",
                "Properties": {
                    "Description": "sim2real rds2 out-of-range rollback",
                    "Family": family,
                    "Parameters": {_PARAM: {"Ref": "LockWait"}},
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
        "Outputs": {"GroupName": {"Value": {"Ref": "DbParams"}}},
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template),
                     Parameters=[{"ParameterKey": "LockWait", "ParameterValue": "120"}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    assert _wait_terminal(cfn, stack_name, 600) == "CREATE_COMPLETE", "stack create did not complete"
    group = {o["OutputKey"]: o["OutputValue"]
             for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}["GroupName"]
    assert _user_value(rds, group) == "120", f"after create {_PARAM} was {_user_value(rds, group)!r}"

    # Positive control: an in-range update applies.
    _update(cfn, stack_name, "300")
    st = _wait_terminal(cfn, stack_name, 600)
    assert st == "UPDATE_COMPLETE", f"in-range update ended {st!r}"
    assert _user_value(rds, group) == "300", f"after in-range update {_PARAM} was {_user_value(rds, group)!r}"

    # Break exactly one thing: the value is one below AllowedValues' lower bound.
    t0 = time.time()
    _update(cfn, stack_name, bad)
    st = _wait_terminal(cfn, stack_name, 900)
    assert st == "UPDATE_ROLLBACK_COMPLETE", (
        f"update to out-of-range {_PARAM}={bad} ended {st!r}, expected UPDATE_ROLLBACK_COMPLETE")
    failed = [e for e in _events_since(cfn, stack_name, t0)
              if e["LogicalResourceId"] == "DbParams" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(failed) == 1, (
        f"expected exactly one DbParams UPDATE_FAILED event, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in failed]!r}")
    # message varies: the UPDATE_FAILED ResourceStatusReason embeds a per-call RDS Request ID
    # and a CloudFormation RequestToken, so the RDS refusal inside it is its asserted stable part
    # (and the same refusal is graded exactly on the direct API call below).
    reason = failed[0].get("ResourceStatusReason") or ""
    refusal = f"Value: {bad} is outside of range: {allowed} for parameter: {_PARAM}"
    assert refusal in reason, f"expected the UPDATE_FAILED reason to carry {refusal!r}, got {reason!r}"
    # Effect absent: the rollback left the last ACCEPTED value, not the rejected one.
    assert _user_value(rds, group) == "300", (
        f"after rolled-back update {_PARAM} was {_user_value(rds, group)!r}, expected '300'")

    # The same boundary on the API the stack's handler calls: exact code, value unchanged.
    code, message = _client_error(lambda: rds.modify_db_parameter_group(
        DBParameterGroupName=group,
        Parameters=[{"ParameterName": _PARAM, "ParameterValue": bad, "ApplyMethod": "immediate"}]))
    assert code == "InvalidParameterValue", f"ModifyDBParameterGroup({bad}) returned {code!r}"
    assert message == (
        f"Value: {bad} is outside of range: {allowed} for parameter: {_PARAM}"
    ), message
    assert _user_value(rds, group) == "300", f"after refused modify {_PARAM} was {_user_value(rds, group)!r}"



def _allowed_values(rds, family):
    for page in rds.get_paginator("describe_engine_default_parameters").paginate(
            DBParameterGroupFamily=family):
        for p in page["EngineDefaults"]["Parameters"]:
            if p["ParameterName"] == _PARAM:
                return p["AllowedValues"]
    raise AssertionError(f"{_PARAM} not in engine defaults for {family!r}")


def _user_value(rds, group):
    for page in rds.get_paginator("describe_db_parameters").paginate(
            DBParameterGroupName=group, Source="user"):
        for p in page["Parameters"]:
            if p["ParameterName"] == _PARAM:
                return p.get("ParameterValue")
    return None


def _update(cfn, stack_name, value):
    cfn.update_stack(StackName=stack_name, UsePreviousTemplate=True,
                     Parameters=[{"ParameterKey": "LockWait", "ParameterValue": value}])


def _wait_terminal(cfn, stack_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        st = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not st.endswith("_IN_PROGRESS"):
            return st
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {st!r} after {timeout_s}s")
        time.sleep(5)


def _events_since(cfn, stack_name, t0):
    out, token = [], None
    while True:
        kw = {"StackName": stack_name}
        if token:
            kw["NextToken"] = token
        d = cfn.describe_stack_events(**kw)
        for e in d["StackEvents"]:
            if e["Timestamp"].timestamp() < t0 - 5:
                return out
            out.append(e)
        token = d.get("NextToken")
        if not token:
            return out


def _client_error(fn):
    """Call fn() and return the (code, message) of the service error it raises. An unexpected
    success raises AssertionError."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp is None:
            raise
        return resp["Error"]["Code"], resp["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _delete_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                st = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            except cfn.exceptions.ClientError:
                return
            if st == "DELETE_COMPLETE":
                return
            if st == "DELETE_FAILED":
                raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
            time.sleep(5)
        raise RuntimeError(f"stack {stack_name} not deleted within 600s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_name} delete raised {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
