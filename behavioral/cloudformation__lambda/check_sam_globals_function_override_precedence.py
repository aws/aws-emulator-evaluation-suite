"""sam-globals-function-override-precedence."""

from __future__ import annotations

import json
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-globals-function-override-precedence"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_globals_precedence"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A function-level primitive replaces its Globals value while maps (Environment, Tags) merge
    key by key with the function winning, and the running code sees the merged environment.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-template-anatomy-globals.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    inherits = ctx.unique_name("sim2real-sam-gin-")
    overrides = ctx.unique_name("sim2real-sam-gov-")
    stack = ctx.unique_name("sim2real-sam-glob-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    for fn in (inherits, overrides):
        ctx.on_cleanup(lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    _create_stack(ctx, cfn, stack, body, {"InheritsName": inherits, "OverridesName": overrides})

    want = {
        inherits: (256, 7, {"ALPHA": "global", "BRAVO": "global"},
                   {"lambda:createdBy": "SAM", "tier": "global", "owner": "global"}),
        overrides: (512, 7, {"ALPHA": "global", "BRAVO": "function", "CHARLIE": "function"},
                    {"lambda:createdBy": "SAM", "tier": "global", "owner": "function"}),
    }
    for fn, (memory, timeout, env, fn_tags) in want.items():
        config = lam.get_function_configuration(FunctionName=fn)
        got = (config["MemorySize"], config["Timeout"], config["Runtime"],
               config["Environment"]["Variables"])
        assert got == (memory, timeout, "python3.13", env), (
            f"{fn}: (MemorySize, Timeout, Runtime, Environment) {got!r}, expected "
            f"{(memory, timeout, 'python3.13', env)!r}")
        # CloudFormation adds aws:cloudformation:* and propagates the stack's own tag.
        listed = {k: v for k, v in lam.list_tags(Resource=config["FunctionArn"])["Tags"].items()
                  if not k.startswith("aws:cloudformation:") and k != "sim2real"}
        assert listed == fn_tags, f"{fn}: tags {listed!r}, expected {fn_tags!r}"
        seen = _invoke(lam, fn)
        expected = {k: env.get(k) for k in ("ALPHA", "BRAVO", "CHARLIE")}
        assert seen == expected, f"{fn}: the running code saw {seen!r}, expected {expected!r}"


def _invoke(lam, fn: str) -> dict:
    """Decoded payload of a synchronous invoke that must not raise."""
    out = lam.invoke(FunctionName=fn, Payload=b"{}")
    body = out["Payload"].read().decode()
    assert "FunctionError" not in out, f"{fn} raised: {body[:300]!r}"
    return json.loads(body)


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
