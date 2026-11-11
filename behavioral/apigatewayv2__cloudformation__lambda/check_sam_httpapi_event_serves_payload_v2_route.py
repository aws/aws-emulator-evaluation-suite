"""sam-httpapi-event-serves-payload-v2-route."""

from __future__ import annotations

import time
from pathlib import Path

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-httpapi-event-serves-payload-v2-route"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_httpapi"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HttpApi event serves its route through the $default stage with a 2.0 payload once
    Globals.Function's MemorySize reaches the function, Globals.HttpApi CORS answers only the
    allowed origin, and an undeclared route is a 404.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-httpapi.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-http-")
    stack = ctx.unique_name("sim2real-sam-http-")
    origin = f"https://{ctx.unique_name('sim2real-')}.example.com"
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body, {"FunctionName": fn, "AllowedOrigin": origin})
    assert lam.get_function_configuration(FunctionName=fn)["MemorySize"] == 192, (
        "Globals.Function MemorySize must reach the function")

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    base, headers = ctx.endpoint_route(outputs["Endpoint"])

    def get(path: str, extra: dict) -> requests.Response:
        return requests.get(f"{base}{path}", headers={**headers, **extra},
                            verify=ctx.http_verify, timeout=30)

    # The route answers once the integration permission is in effect.
    resp = _poll(lambda: get("/hello", {"Origin": origin}), lambda r: r.status_code == 200,
                 timeout_s=120.0, interval_s=3.0, what="GET /hello answering 200")
    assert resp.json() == {"version": "2.0", "routeKey": "GET /hello", "rawPath": "/hello"}, (
        f"the function must receive a 2.0 payload for GET /hello; got {resp.text[:300]!r}")
    allow = resp.headers.get("access-control-allow-origin")
    assert allow == origin, f"an allowed origin must be echoed by CORS; got {allow!r}"

    other = get("/hello", {"Origin": "https://not-allowed.example.org"})
    assert other.status_code == 200, f"a foreign origin still reaches the route; got {other.status_code}"
    assert "access-control-allow-origin" not in other.headers, (
        f"CORS must not answer a foreign origin; headers {dict(other.headers)!r}")

    missing = get("/missing", {})
    assert (missing.status_code, missing.text) == (404, '{"message":"Not Found"}'), (
        f"an undeclared route must be a 404; got {missing.status_code} {missing.text[:200]!r}")


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
