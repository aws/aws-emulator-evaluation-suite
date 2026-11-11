"""sam-eventbridge-rule-event-matching-invokes-nonmatching-does-not."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "sam-eventbridge-rule-event-matching-invokes-nonmatching-does-not"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_eventbridge_rule"
_TEMPLATE_FILE = ".aws-sam/build/template.yaml"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0
_RULE_LOGICAL_ID = "FnMatch"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:deploy", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A SAM Function's `EventBridgeRule` event becomes a rule targeting it; a PutEvents entry
    matching the declared Pattern reaches the function's own logs, and one that does not match
    (same source and detail-type, a different `detail.kind`) never does.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-eventbridgerule.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-ebr-")
    stack = ctx.unique_name("sim2real-sam-ebr-")
    log_group = f"/aws/lambda/{fn}"
    work = _workdir(ctx, _PROJECT)

    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, ["build", "--region", ctx.region]), "build")
    _ok(_sam(ctx, work, _deploy_args(ctx, stack, {"FunctionName": fn})), "deploy")

    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    rule_name = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=_RULE_LOGICAL_ID
    )["StackResourceDetail"]["PhysicalResourceId"]
    rule = events.describe_rule(Name=rule_name)
    assert rule["State"] == "ENABLED", f"the generated rule must be ENABLED; got {rule['State']!r}"
    pattern = json.loads(rule["EventPattern"])
    assert pattern == {"source": ["sim2real.custom"], "detail-type": ["sim2real.marker"],
                       "detail": {"kind": ["match-me"]}}, (
        f"the generated rule's EventPattern reads back {pattern!r}"
    )
    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert [t["Arn"] for t in targets] == [fn_arn], (
        f"the rule must target exactly the deployed function; got {targets!r}"
    )

    token_match = ctx.unique_name("sim2real-match-")
    positive_start = time.monotonic()
    events.put_events(Entries=[{
        "Source": "sim2real.custom", "DetailType": "sim2real.marker",
        "Detail": f'{{"kind": "match-me", "token": "{token_match}"}}',
    }])
    _wait_logged(logs, log_group, token_match, timeout_s=240.0)
    positive_latency_s = time.monotonic() - positive_start

    token_mismatch = ctx.unique_name("sim2real-mismatch-")
    events.put_events(Entries=[{
        "Source": "sim2real.custom", "DetailType": "sim2real.marker",
        "Detail": f'{{"kind": "not-a-match", "token": "{token_mismatch}"}}',
    }])
    absence_window_s = max(3 * positive_latency_s, 30.0)
    leaked = _wait_logged(logs, log_group, token_mismatch, timeout_s=absence_window_s,
                          want_absence=True)
    assert not leaked, (
        f"a PutEvents entry whose detail.kind does not match the rule's Pattern must never reach "
        f"the function; found token {token_mismatch!r} in {log_group!r}"
    )

    # Close the loop: the rule (and the log group) are still live after the non-match.
    token_again = ctx.unique_name("sim2real-match-")
    events.put_events(Entries=[{
        "Source": "sim2real.custom", "DetailType": "sim2real.marker",
        "Detail": f'{{"kind": "match-me", "token": "{token_again}"}}',
    }])
    _wait_logged(logs, log_group, token_again, timeout_s=240.0)
    assert not _wait_logged(logs, log_group, token_mismatch, timeout_s=0.0, want_absence=True), (
        f"the non-matching token {token_mismatch!r} reached the function after all"
    )

    roles = _stack_roles(cfn, stack_id)
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _delete_stack_named(cfn, stack)
    _assert_roles_gone(ctx.client("iam"), roles)

    gone_rule = _absent(lambda: events.describe_rule(Name=rule_name))
    assert gone_rule == (
        "ResourceNotFoundException", f"Rule {rule_name} does not exist on EventBus default.",
    ), f"DescribeRule after the in-band delete must name the rule's own name; got {gone_rule!r}"
    gone_fn = _absent(lambda: lam.get_function(FunctionName=fn))
    assert gone_fn == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}",
    ), f"GetFunction after the in-band delete must name the function's own ARN; got {gone_fn!r}"


def _wait_logged(logs, log_group: str, token: str, *, timeout_s: float,
                 want_absence: bool = False) -> bool:
    """Poll the log group for the handler's own ``MARKER=<token>`` print; return whether seen.

    Raises on timeout unless ``want_absence``, in which case timing out without seeing it is the
    expected outcome and the method returns False.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            events = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{token}"')[
                "events"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            events = []
        if events:
            return True
        if time.monotonic() >= deadline:
            if want_absence:
                return False
            raise AssertionError(f"{token!r} never appeared in {log_group!r} within {timeout_s}s")
        time.sleep(2.0)


def _absent(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


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
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack `sam deploy` created under `name`, if it exists, and wait for DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run(
        [sam, *args], cwd=cwd, env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
        capture_output=True, text=True, timeout=timeout_s,
    )


def _ok(result, what: str) -> None:
    """Assert a SAM CLI run exited 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}"
    )


def _deploy_args(ctx, stack: str, params: dict) -> list:
    """`sam deploy` of the built template; InlineCode needs no packaging bucket."""
    overrides = [f"{k}={v}" for k, v in params.items()]
    return [
        "deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
        "--capabilities", *_CAPS, "--region", ctx.region,
        "--no-confirm-changeset", "--no-progressbar",
        "--parameter-overrides", *overrides,
        "--tags", f"sim2real={CHECK}",
    ]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
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


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
