"""deploy-apigatewayv2-1-dangling-route-target-rejected-rolls-back-api."""
from __future__ import annotations

import sys
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-1-dangling-route-target-rejected-rolls-back-api"
GROUP = "deploy"
SERVICES = ["apigatewayv2"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = DEPLOYMENTS / "http-api-dangling-route-target.yaml"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A stack whose Route targets a never-created integration fails on exactly that Route, reaches
    ROLLBACK_COMPLETE and deletes the Api it made; the same template with a real target creates.
    """
    ctx.verify_account_safety()
    assert _TEMPLATE.is_file(), f"the deploy artifact must exist on disk at {_TEMPLATE}"
    agw = ctx.client("apigatewayv2")
    cfn = ctx.client("cloudformation")

    # Positive control: the same template with a real integration target.
    ok_stack = ctx.unique_name("sim2real-apigwv2-cfn-ok-")
    _create_stack(ctx, ok_stack, {"TargetMode": "real", "ApiName": ok_stack})
    status, reason = _wait_terminal(ctx, ok_stack)
    assert status == "CREATE_COMPLETE", (
        f"the control stack (real integration target) must create cleanly, got {status}: {reason!r}"
    )
    ok_api = {o["OutputKey"]: o["OutputValue"]
              for o in cfn.describe_stacks(StackName=ok_stack)["Stacks"][0].get("Outputs", [])
              }["ApiIdOut"]
    assert agw.get_api(ApiId=ok_api).get("ProtocolType") == "HTTP", "control Api must exist as HTTP"
    integ = _physical_id(ctx, ok_stack, "RealIntegration")
    targets = {r["RouteKey"]: r.get("Target") for r in agw.get_routes(ApiId=ok_api).get("Items") or []}
    assert targets.get("GET /bad") == f"integrations/{integ}", (
        f"the control's second route must target the real integration {integ!r}, got {targets!r}"
    )
    assert set(targets) == {"GET /ok", "GET /bad"}, f"control routes: {sorted(targets)!r}"

    # The one target dangles.
    bad_stack = ctx.unique_name("sim2real-apigwv2-cfn-bad-")
    _create_stack(ctx, bad_stack, {"TargetMode": "dangling", "ApiName": bad_stack})
    status, reason = _wait_terminal(ctx, bad_stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Route targeting a never-created integration must fail the create and roll back, the "
        f"stack ended {status}: {reason!r}"
    )

    # The rolled-back Api's id is only recoverable from the stack's event history.
    events = _stack_events(ctx, bad_stack)
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"
              and e.get("LogicalResourceId") != bad_stack
              and "cancelled" not in (e.get("ResourceStatusReason") or "").lower()]
    assert [e["LogicalResourceId"] for e in failed] == ["BadRoute"], (
        f"the root-cause failure must be the dangling BadRoute and nothing else, CREATE_FAILED "
        f"resources: {[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    api_created = [e for e in events if e.get("LogicalResourceId") == "HttpApi"
                   and e.get("ResourceStatus") == "CREATE_COMPLETE"]
    assert len(api_created) == 1 and api_created[0].get("PhysicalResourceId"), (
        f"the Api must have been created before the failing Route, HttpApi events: "
        f"{[(e.get('ResourceStatus'), e.get('PhysicalResourceId')) for e in events if e.get('LogicalResourceId') == 'HttpApi']!r}"
    )
    bad_api = api_created[0]["PhysicalResourceId"]
    api_deleted = [e for e in events if e.get("LogicalResourceId") == "HttpApi"
                   and e.get("ResourceStatus") == "DELETE_COMPLETE"]
    assert len(api_deleted) == 1, (
        f"the create-rollback must delete the Api it created, HttpApi events: "
        f"{[e.get('ResourceStatus') for e in events if e.get('LogicalResourceId') == 'HttpApi']!r}"
    )

    code, message = _error_code(lambda: agw.get_api(ApiId=bad_api))
    assert code == "NotFoundException", (
        f"GetApi on the rolled-back ApiId {bad_api!r} must be NotFoundException, got {code!r}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bad_api}", (
        f"unexpected GetApi NotFoundException message: {message!r}"
    )
    # The control Api is untouched by the sibling stack's rollback.
    assert agw.get_api(ApiId=ok_api).get("ApiId") == ok_api, "the control Api must still exist"



def _error_code(fn) -> tuple[str, str | None]:
    """(code, message) of the AWS error fn() raised. RAISES if fn() succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message")
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack_status(ctx, stack_name):
    try:
        st = ctx.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0]
    except ClientError:
        return ("GONE", None)
    return (st["StackStatus"], st.get("StackStatusReason"))


def _delete_stack_and_wait(ctx, stack_name, *, timeout_s=600.0) -> None:
    """Teardown: delete the stack and wait; a failure raises."""
    try:
        ctx.client("cloudformation").delete_stack(StackName=stack_name)
        final = _poll_until(
            lambda: _stack_status(ctx, stack_name)[0],
            lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
            timeout_s=timeout_s, interval_s=5.0, description=f"delete stack {stack_name}",
        )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f"stack {stack_name} delete did not complete: {exc}") from exc
        return
    if final == "DELETE_FAILED":
        raise RuntimeError(f"stack {stack_name} ended DELETE_FAILED")


def _create_stack(ctx, stack_name, parameters) -> None:
    """CreateStack with the default OnFailure (ROLLBACK); teardown registered immediately."""
    ctx.client("cloudformation").create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE.read_text(),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))


def _wait_terminal(ctx, stack_name, *, timeout_s=600.0):
    return _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: not s[0].endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, interval_s=5.0, description=f"stack {stack_name} terminal state",
    )


def _stack_events(ctx, stack_name) -> list:
    pages = ctx.client("cloudformation").get_paginator("describe_stack_events").paginate(
        StackName=stack_name
    )
    return [e for p in pages for e in p.get("StackEvents") or []]


def _physical_id(ctx, stack_name, logical_id) -> str:
    return ctx.client("cloudformation").describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
