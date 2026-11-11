"""sam-autopublish-codesha256-governs-version-publication."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-autopublish-codesha256-governs-version-publication"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_autopublish_codesha256"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """With AutoPublishCodeSha256 a code change under the same value publishes no version and the
    alias keeps serving the old code; a new value publishes version 2 and moves the alias.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-autopublishcodesha256
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-sha-")
    stack = ctx.unique_name("sim2real-sam-sha-")
    first, second = ctx.unique_name("r1-"), ctx.unique_name("r2-")
    sha_a = hashlib.sha256(first.encode()).hexdigest()
    sha_b = hashlib.sha256(second.encode()).hexdigest()
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body,
                             {"FunctionName": fn, "Reply": first, "CodeSha": sha_a})
    v1 = _version_ids(cfn, stack_id)
    assert v1 == [f"FnVersion{sha_a[:10]}"], f"generated versions {v1!r}"
    description = lam.get_function_configuration(FunctionName=fn)["Description"]
    assert description == sha_a, (
        f"SAM puts the AutoPublishCodeSha256 value in the function description; got {description!r}")
    assert _invoke(lam, fn, "live") == ({"reply": first}, "1"), "live must serve version 1"

    _update(cfn, stack_id, {"Reply": second, "CodeSha": sha_a}, body=body)
    v_same = _version_ids(cfn, stack_id)
    assert v_same == v1, f"an unchanged AutoPublishCodeSha256 must keep {v1!r}; got {v_same!r}"
    versions = [v["Version"] for v in lam.list_versions_by_function(FunctionName=fn)["Versions"]]
    assert versions == ["$LATEST", "1"], f"no version may be published; got {versions!r}"
    assert _invoke(lam, fn) == ({"reply": second}, "$LATEST"), "$LATEST must run the new code"
    assert _invoke(lam, fn, "live") == ({"reply": first}, "1"), (
        "the alias must keep serving version 1's code")

    _update(cfn, stack_id, {"Reply": second, "CodeSha": sha_b}, body=body)
    v2 = _version_ids(cfn, stack_id)
    assert v2 == [f"FnVersion{sha_b[:10]}"], (
        f"a new AutoPublishCodeSha256 must re-key the Version; got {v2!r}")
    versions = [v["Version"] for v in lam.list_versions_by_function(FunctionName=fn)["Versions"]]
    assert versions == ["$LATEST", "1", "2"], f"version 2 must be published; got {versions!r}"
    assert lam.get_alias(FunctionName=fn, Name="live")["FunctionVersion"] == "2", (
        "the live alias must move to version 2")
    assert _invoke(lam, fn, "live") == ({"reply": second}, "2"), "live must serve the new code"


def _version_ids(cfn, stack_id: str) -> list:
    resources = _processed(cfn, stack_id)["Resources"]
    return sorted(lid for lid, r in resources.items() if r["Type"] == "AWS::Lambda::Version")


def _update(cfn, stack_id: str, values: dict, *, body: str) -> None:
    """Update parameters on the previous template; assert UPDATE_COMPLETE."""
    params = [{"ParameterKey": "FunctionName", "UsePreviousValue": True}]
    params += [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]
    before = _stamp(cfn, stack_id)[1]
    cfn.update_stack(StackName=stack_id, TemplateBody=body, Capabilities=_CAPS,
                     Parameters=params)
    status, _ = _poll(lambda: _stamp(cfn, stack_id),
                      lambda s: s[1] != before and not s[0].endswith("_IN_PROGRESS"),
                      timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} updated")
    assert status == "UPDATE_COMPLETE", f"update ended {status}: {_failures(cfn, stack_id)!r}"


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
