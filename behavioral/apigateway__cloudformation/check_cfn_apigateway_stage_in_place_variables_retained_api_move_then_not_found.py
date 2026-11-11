"""cfn-apigateway-stage-in-place-variables-retained-api-move-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigateway-stage-in-place-variables-retained-api-move-then-not-found"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_STAGE = "live"

#: API Gateway's refusal of a REST API that no longer exists, naming account and API id.
_NOT_FOUND_CODE = "NotFoundException"
_NOT_FOUND_MESSAGE = "Invalid API identifier specified {account}:{api_id}"
#: API Gateway's refusal of a stage that no longer exists in an existing API.
_STAGE_GONE = (_NOT_FOUND_CODE, "Invalid stage identifier specified")
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: The verb each API's single MOCK method answers, so each stage's export names its API.
_VERBS = {"ApiA": "GET", "ApiB": "POST"}


def _template(names: dict[str, str], api: str | None, description: str, greeting: str) -> str:
    """Two deployed REST APIs; with *api*, a stage of that API's deployment."""
    resources: dict = {}
    for logical, verb in _VERBS.items():
        resources[logical] = {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {
                "Name": names[logical],
                "EndpointConfiguration": {"Types": ["REGIONAL"]},
                # No default execute-api endpoint: the stage is never reachable publicly.
                "DisableExecuteApiEndpoint": True,
                "Tags": _TAGS,
            },
        }
        resources[f"{logical}Method"] = {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": logical},
                "ResourceId": {"Fn::GetAtt": [logical, "RootResourceId"]},
                "HttpMethod": verb,
                "AuthorizationType": "AWS_IAM",
                "Integration": {
                    "Type": "MOCK",
                    "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                    "IntegrationResponses": [{"StatusCode": "200"}],
                },
                "MethodResponses": [{"StatusCode": "200"}],
            },
        }
        resources[f"{logical}Deployment"] = {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": f"{logical}Method",
            "Properties": {"RestApiId": {"Ref": logical}},
        }
    if api is not None:
        resources["Stage"] = {
            "Type": "AWS::ApiGateway::Stage",
            # RestApiId is create-only, so moving the stage replaces it.
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "RestApiId": {"Ref": api},
                "DeploymentId": {"Ref": f"{api}Deployment"},
                "StageName": _STAGE,
                "Description": description,
                "Variables": {"greeting": greeting},
                "Tags": _TAGS,
            },
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stage reads back its deployment's snapshot (GetExport); it updates in place.

    Description and Variables change in place; a RestApiId change under UpdateReplacePolicy Retain
    keeps the old API's stage; removal and delete answer NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-stage.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    names = {logical: ctx.unique_name(f"sim2real-cfnstg-{logical.lower()}-") for logical in _VERBS}
    stack_name = ctx.unique_name("sim2real-cfnstg-stack-")
    ref = {"stack": stack_name}

    # The retained stage lives inside API A, which the stack delete removes.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, API Gateway's view, and the stage's export
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(names, "ApiA", "first", "hello"), Tags=_TAGS
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    api_a, api_b = ids["ApiA"], ids["ApiB"]
    dep_a, dep_b = ids["ApiADeployment"], ids["ApiBDeployment"]
    assert ids["Stage"] == _STAGE, f"the stage's physical id must be its StageName: {ids!r}"
    _assert_stage(apigw, api_a, dep_a, "first", "hello")
    _assert_export(apigw, api_a, names["ApiA"], "get")

    # ---- 2. in-place: a new Description and stage variable on the same stage
    events = _update(ctx, cfn, ref, _template(names, "ApiA", "second", "bonjour"))
    _assert_in_place(_rows(events, set(), "Stage"), _STAGE, "Stage")
    _assert_stage(apigw, api_a, dep_a, "second", "bonjour")

    # ---- 3. replacement under UpdateReplacePolicy Retain: API B staged, API A's stage kept
    events = _update(ctx, cfn, ref, _template(names, "ApiB", "second", "bonjour"))
    # The new stage completes as "live"; CloudFormation reports the skipped delete of the old
    # stage with an empty physical id, after the new one completes. GetStage on API A below
    # shows the old stage kept.
    rows = _rows(events, set(), "Stage")
    statuses = [status for status, _, _ in rows]
    assert ("UPDATE_IN_PROGRESS", _REPLACING) in [(s, r) for s, r, _ in rows], (
        f"Stage must announce its replacement, its events were {rows!r}"
    )
    assert ("UPDATE_COMPLETE", _STAGE) in [(s, pid) for s, _, pid in rows], (
        f"Stage must complete as {_STAGE!r}, its events were {rows!r}"
    )
    old_rows = [(s, pid) for s, _, pid in rows if s.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", "")], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced stage, the delete events of "
        f"Stage were {old_rows!r}"
    )
    assert statuses.index("UPDATE_COMPLETE") < statuses.index("DELETE_SKIPPED"), (
        f"the new stage must complete before the old one is skipped, its events were {rows!r}"
    )
    _assert_stage(apigw, api_b, dep_b, "second", "bonjour")
    _assert_export(apigw, api_b, names["ApiB"], "post")
    _assert_stage(apigw, api_a, dep_a, "second", "bonjour")
    _assert_export(apigw, api_a, names["ApiA"], "get")

    # ---- 4. removal from the template: CloudFormation deletes API B's stage
    events = _update(ctx, cfn, ref, _template(names, None, "", ""))
    deleted = [s for s, _, _ in _rows(events, set(), "Stage")]
    assert deleted == ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], f"removal events: {deleted!r}"
    got = _wait_error(
        ctx,
        lambda: apigw.get_stage(restApiId=api_b, stageName=_STAGE),
        _NOT_FOUND_CODE,
        f"stage {_STAGE} of {api_b}",
    )
    assert got == _STAGE_GONE, f"GetStage after removal answered {got!r}"
    _assert_stage(apigw, api_a, dep_a, "second", "bonjour")

    # ---- 5. delete: API Gateway no longer knows either API
    _delete_stack(ctx, cfn, ref["stack"])
    for api_id in (api_a, api_b):
        got = _wait_error(
            ctx, lambda a=api_id: apigw.get_rest_api(restApiId=a), _NOT_FOUND_CODE, f"API {api_id}"
        )
        want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account, api_id=api_id))
        assert got == want, f"GetRestApi after the stack delete answered {got!r}, expected {want!r}"


def _assert_stage(apigw, api_id: str, dep_id: str, description: str, greeting: str) -> None:
    """GetStage reports the template's deployment, Description, Variables and tag exactly."""
    stage = apigw.get_stage(restApiId=api_id, stageName=_STAGE)
    got = {
        "stageName": stage.get("stageName"),
        "deploymentId": stage.get("deploymentId"),
        "description": stage.get("description"),
        "variables": stage.get("variables"),
        "tag": stage.get("tags", {}).get("sim2real"),
    }
    want = {
        "stageName": _STAGE,
        "deploymentId": dep_id,
        "description": description,
        "variables": {"greeting": greeting},
        "tag": CHECK,
    }
    assert got == want, f"GetStage {_STAGE} of {api_id}: {got!r}, expected {want!r}"


def _assert_export(apigw, api_id: str, api_name: str, verb: str) -> None:
    """The stage's OpenAPI export is its deployment's snapshot: the API's title and one method."""
    resp = apigw.get_export(
        restApiId=api_id, stageName=_STAGE, exportType="oas30", accepts="application/json"
    )
    doc = json.loads(resp["body"].read())
    got = (
        doc.get("info", {}).get("title"),
        {path: sorted(ops) for path, ops in doc.get("paths", {}).items()},
    )
    assert got == (api_name, {"/": [verb]}), (
        f"GetExport of stage {_STAGE} of {api_id}: {got!r}, expected ({api_name!r}, / {verb})"
    )


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ctx=None
    and waits the full cap; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits use fixed caps (ctx=None), never the run's remaining time.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _update(ctx, cfn, ref: dict, body: str, **kwargs) -> list[dict]:
    """UpdateStack to *body*, require UPDATE_COMPLETE, and return the events it added."""
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=body, Tags=_TAGS, **kwargs)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    return [e for e in _events(cfn, ref["stack"]) if e["EventId"] not in seen]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
