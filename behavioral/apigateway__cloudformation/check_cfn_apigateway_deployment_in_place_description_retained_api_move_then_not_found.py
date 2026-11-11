"""cfn-apigateway-deployment-in-place-description-retained-api-move-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigateway-deployment-in-place-description-retained-api-move-then-not-found"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: API Gateway's refusal of a REST API that no longer exists, naming account and API id.
_NOT_FOUND_CODE = "NotFoundException"
_NOT_FOUND_MESSAGE = "Invalid API identifier specified {account}:{api_id}"
#: API Gateway's refusal of a deployment that no longer exists in an existing API.
_DEPLOYMENT_GONE = (_NOT_FOUND_CODE, "Invalid Deployment identifier specified")
#: The verb each API's single MOCK method answers, so each snapshot names its API.
_VERBS = {"ApiA": "GET", "ApiB": "POST"}


def _template(names: dict[str, str], api: str | None, description: str) -> str:
    """Two REST APIs with one MOCK method each; with *api*, a deployment of that API."""
    resources: dict = {}
    for logical, verb in _VERBS.items():
        resources[logical] = {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {
                "Name": names[logical],
                "EndpointConfiguration": {"Types": ["REGIONAL"]},
                # No default execute-api endpoint: nothing here is reachable publicly.
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
    if api is not None:
        resources["Deployment"] = {
            "Type": "AWS::ApiGateway::Deployment",
            # A deployment snapshots its API's methods, so it is created after them.
            "DependsOn": [f"{logical}Method" for logical in _VERBS],
            # RestApiId is create-only, so moving the deployment replaces it.
            "UpdateReplacePolicy": "Retain",
            "Properties": {"RestApiId": {"Ref": api}, "Description": description},
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation deployment reads back its API's method snapshot; it updates in place.

    A RestApiId change under UpdateReplacePolicy Retain deploys the other API and keeps the old
    deployment; removal answers NotFoundException, and so does the deleted stack's API.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-deployment.html
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    names = {logical: ctx.unique_name(f"sim2real-cfndep-{logical.lower()}-") for logical in _VERBS}
    stack_name = ctx.unique_name("sim2real-cfndep-stack-")
    ref = {"stack": stack_name}

    # The retained deployment lives inside API A, which the stack delete removes.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, API Gateway's view, and the snapshot of API A
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(names, "ApiA", "first"), Tags=_TAGS
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    api_a, api_b, old_dep = ids["ApiA"], ids["ApiB"], ids["Deployment"]
    _assert_deployment(apigw, api_a, old_dep, "first", "GET")

    # ---- 2. in-place: a new Description on the same deployment
    events = _update(ctx, cfn, ref, _template(names, "ApiA", "second"))
    assert _physical_ids(cfn, ref["stack"])["Deployment"] == old_dep, "in place keeps the id"
    _assert_in_place(_rows(events, set(), "Deployment"), old_dep, "Deployment")
    _assert_deployment(apigw, api_a, old_dep, "second", "GET")

    # ---- 3. replacement under UpdateReplacePolicy Retain: API B deployed, A's deployment kept
    events = _update(ctx, cfn, ref, _template(names, "ApiB", "second"))
    new_dep = _physical_ids(cfn, ref["stack"])["Deployment"]
    assert new_dep != old_dep, f"a RestApiId change must replace the deployment: {new_dep!r}"
    _assert_replaced_and_retained(
        _rows(events, set(), "Deployment"), old_dep, new_dep, "Deployment"
    )
    _assert_deployment(apigw, api_b, new_dep, "second", "POST")
    _assert_deployment(apigw, api_a, old_dep, "second", "GET")

    # ---- 4. removal from the template: CloudFormation deletes the deployment it tracks
    events = _update(ctx, cfn, ref, _template(names, None, ""))
    deleted = [s for s, _, pid in _rows(events, set(), "Deployment") if pid == new_dep]
    assert deleted == ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"], f"removal events: {deleted!r}"
    got = _wait_error(
        ctx,
        lambda: apigw.get_deployment(restApiId=api_b, deploymentId=new_dep),
        _NOT_FOUND_CODE,
        f"deployment {new_dep}",
    )
    assert got == _DEPLOYMENT_GONE, f"GetDeployment after removal answered {got!r}"
    _assert_deployment(apigw, api_a, old_dep, "second", "GET")

    # ---- 5. delete: API Gateway no longer knows either API
    _delete_stack(ctx, cfn, ref["stack"])
    for api_id in (api_a, api_b):
        got = _wait_error(
            ctx, lambda a=api_id: apigw.get_rest_api(restApiId=a), _NOT_FOUND_CODE, f"API {api_id}"
        )
        want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account, api_id=api_id))
        assert got == want, f"GetRestApi after the stack delete answered {got!r}, expected {want!r}"


def _assert_deployment(apigw, api_id: str, dep_id: str, description: str, verb: str) -> None:
    """GetDeployment reports the Description and a snapshot holding the API's one method."""
    dep = apigw.get_deployment(restApiId=api_id, deploymentId=dep_id, embed=["apisummary"])
    got = {
        "id": dep.get("id"),
        "description": dep.get("description"),
        "summary": dep.get("apiSummary"),
    }
    want = {
        "id": dep_id,
        "description": description,
        "summary": {"/": {verb: {"authorizationType": "AWS_IAM", "apiKeyRequired": False}}},
    }
    assert got == want, f"GetDeployment {dep_id} of {api_id}: {got!r}, expected {want!r}"


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


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
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
