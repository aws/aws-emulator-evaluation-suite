"""sam-function-globals-autopublishalias-publishes-new-version."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-function-globals-autopublishalias-publishes-new-version"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_globals_autopublishalias"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0
_VERSION_ID = re.compile(r"^FnVersion[0-9a-f]{10}$")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """AutoPublishAlias expands to a hashed Version and a `live` alias; a code change publishes
    version 2 and moves the alias, version 1 stays invokable, and Globals reach the function.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-autopublishalias
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-gapa-")
    stack = ctx.unique_name("sim2real-sam-gapa-")
    first, second = ctx.unique_name("r1-"), ctx.unique_name("r2-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body, {"FunctionName": fn, "Reply": first})

    processed = _processed(cfn, stack_id)
    types = {lid: r["Type"] for lid, r in processed["Resources"].items()}
    v1 = [lid for lid, t in types.items() if t == "AWS::Lambda::Version"]
    assert len(v1) == 1 and _VERSION_ID.match(v1[0]), (
        f"the processed template must hold one hashed FnVersion<10 hex>; resources {types!r}")
    assert processed["Resources"][v1[0]].get("DeletionPolicy") == "Retain", (
        f"the generated Version must be retained; got {processed['Resources'][v1[0]]!r}")
    alias = processed["Resources"].get("FnAliaslive", {})
    assert alias.get("Type") == "AWS::Lambda::Alias", f"no FnAliaslive alias in {types!r}"
    assert alias["Properties"]["Name"] == "live", f"alias properties {alias['Properties']!r}"
    assert alias["Properties"]["FunctionVersion"] == {"Fn::GetAtt": [v1[0], "Version"]}, (
        f"the alias must follow the generated version; got {alias['Properties']!r}")
    leftover = sorted(t for t in types.values() if t.startswith("AWS::Serverless::"))
    assert leftover == [], f"serverless types survived the transform: {leftover!r}"

    config = lam.get_function_configuration(FunctionName=fn)
    got = (config["Runtime"], config["MemorySize"], config["Timeout"], config["Handler"],
           config["Environment"]["Variables"])
    assert got == ("python3.13", 256, 5, "index.handler", {"MODE": "global"}), (
        f"Globals.Function values did not reach the function: {got!r}")
    assert lam.get_alias(FunctionName=fn, Name="live")["FunctionVersion"] == "1", (
        "the live alias must point at version 1 after the create")
    payload, executed = _invoke(lam, fn, "live")
    assert (payload, executed) == ({"reply": first, "mode": "global"}, "1"), (
        f"invoking live returned {payload!r} from version {executed!r}")

    before = _stamp(cfn, stack_id)[1]
    cfn.update_stack(
        StackName=stack_id, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": "FunctionName", "UsePreviousValue": True},
                    {"ParameterKey": "Reply", "ParameterValue": second}])
    status, _ = _poll(lambda: _stamp(cfn, stack_id),
                      lambda s: s[1] != before and not s[0].endswith("_IN_PROGRESS"),
                      timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} updated")
    assert status == "UPDATE_COMPLETE", f"update ended {status}: {_failures(cfn, stack_id)!r}"

    resources = _processed(cfn, stack_id)["Resources"]
    v2 = [lid for lid, r in resources.items() if r["Type"] == "AWS::Lambda::Version"]
    assert len(v2) == 1, f"the processed template must hold one Version; got {v2!r}"
    assert _VERSION_ID.fullmatch(v2[0]), f"the Version must be a hashed FnVersion<10 hex>; got {v2!r}"
    versions = [v["Version"] for v in lam.list_versions_by_function(FunctionName=fn)["Versions"]]
    assert versions == ["$LATEST", "1", "2"], (
        f"the update must publish version 2 and keep the retained version 1; got {versions!r}")
    assert lam.get_alias(FunctionName=fn, Name="live")["FunctionVersion"] == "2", (
        "the live alias must move to version 2 after the update")
    payload, executed = _invoke(lam, fn, "live")
    assert (payload, executed) == ({"reply": second, "mode": "global"}, "2"), (
        f"invoking live after the update returned {payload!r} from version {executed!r}")
    payload, executed = _invoke(lam, fn, "1")
    assert (payload, executed) == ({"reply": first, "mode": "global"}, "1"), (
        f"the retained version 1 returned {payload!r} from version {executed!r}")


def _stamp(cfn, stack_id: str) -> tuple:
    """(StackStatus, LastUpdatedTime) of the stack."""
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return stack["StackStatus"], stack.get("LastUpdatedTime")


def _invoke(lam, fn: str, qualifier: str | None = None):
    """(decoded payload, ExecutedVersion) of a synchronous invoke that must not raise."""
    kwargs = {"FunctionName": fn, "Payload": b"{}"}
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    out = lam.invoke(**kwargs)
    body = out["Payload"].read().decode()
    assert "FunctionError" not in out, f"{fn}:{qualifier} raised: {body[:300]!r}"
    return json.loads(body), out.get("ExecutedVersion")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 1.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
