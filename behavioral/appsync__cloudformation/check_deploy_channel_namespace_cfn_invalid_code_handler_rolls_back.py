"""deploy-channel-namespace-cfn-invalid-code-handler-rolls-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-channel-namespace-cfn-invalid-code-handler-rolls-back"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) '
    r"\(Service: AppSync, Status Code: \d+, Request ID: [0-9a-f-]+\) "
    r'\(SDK Attempt Count: \d+\)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _poll_stack(cfn, stack_id, timeout_s=300.0):
    """Poll ``DescribeStacks`` until the stack's status settles; return that status."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} stuck at {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _fail_reasons(cfn, stack_id):
    """``{logical id: reason}`` of every non-progress event, for a readable deploy failure."""
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    return {
        e["LogicalResourceId"]: e.get("ResourceStatusReason")
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    }


def _create_reason(cfn, stack_id, logical_id):
    """The single ``CREATE_FAILED`` reason recorded for ``logical_id``."""
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _delete_stack(cfn, stack_id, timeout_s=300.0):
    """Delete the stack by id and wait for ``DELETE_COMPLETE``; a ``DELETE_FAILED`` raises."""
    cfn.delete_stack(StackName=stack_id)
    status = _poll_stack(cfn, stack_id, timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {_fail_reasons(cfn, stack_id)}")


# Valid handler code the control deploys; a plain string with no exported onPublish/onSubscribe
# function is not valid APPSYNC_JS and is what the broken stack deploys instead.
_VALID_HANDLER = (
    "export function onPublish(ctx) {\n  return ctx.events;\n}\n"
    "export function onSubscribe(ctx) {\n}\n"
)
_INVALID_HANDLER = "this is not a valid APPSYNC_JS module"
_REJECTED = ("Error processing APPSYNC_JS code.", "InvalidRequest")


def _template(api_name, ns_name, handler):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EvtApi": {
                "Type": "AWS::AppSync::Api",
                "Properties": {
                    "Name": api_name,
                    "EventConfig": {
                        "AuthProviders": [{"AuthType": "API_KEY"}],
                        "ConnectionAuthModes": [{"AuthType": "API_KEY"}],
                        "DefaultPublishAuthModes": [{"AuthType": "API_KEY"}],
                        "DefaultSubscribeAuthModes": [{"AuthType": "API_KEY"}],
                    },
                },
            },
            "Namespace": {
                "Type": "AWS::AppSync::ChannelNamespace",
                "Properties": {
                    "ApiId": {"Fn::GetAtt": ["EvtApi", "ApiId"]},
                    "Name": ns_name,
                    "CodeHandlers": handler,
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Fn::GetAtt": ["EvtApi", "ApiId"]}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CFN ChannelNamespace whose CodeHandlers is not valid APPSYNC_JS fails the stack create.

    The Api created alongside it rolls back too, while an identical template with valid
    CodeHandlers deploys and reads the handler back.
    """
    cfn = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    good_api_name = ctx.unique_name("sim2real-appsync-nsbad-good-api-")
    bad_api_name = ctx.unique_name("sim2real-appsync-nsbad-bad-api-")

    good_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-appsync-nsbad-good-"),
        TemplateBody=_template(good_api_name, "default", _VALID_HANDLER),
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_id))
    bad_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-appsync-nsbad-bad-"),
        TemplateBody=_template(bad_api_name, "default", _INVALID_HANDLER),
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_id))

    status = _poll_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"broken stack ended {status!r}: {_fail_reasons(cfn, bad_id)}"
    reason = _create_reason(cfn, bad_id, "Namespace")
    match = _HANDLER_REASON.match(reason)
    assert match is not None, f"not a resource-handler failure reason: {reason!r}"
    assert (match["message"], match["code"]) == _REJECTED, (match["message"], match["code"])

    bad_api_id = {o["OutputKey"]: o["OutputValue"]
                  for o in cfn.describe_stacks(StackName=bad_id)["Stacks"][0].get("Outputs", [])
                  }.get("ApiId")
    assert bad_api_id is None, "a rolled-back stack must publish no ApiId output"
    pages = appsync.get_paginator("list_apis").paginate()
    found = [a for page in pages for a in page["apis"] if a["name"] == bad_api_name]
    assert found == [], f"the rolled-back Api must not appear in ListApis: {found!r}"

    status = _poll_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}: {_fail_reasons(cfn, good_id)}"
    good_api_id = {o["OutputKey"]: o["OutputValue"]
                   for o in cfn.describe_stacks(StackName=good_id)["Stacks"][0]["Outputs"]}["ApiId"]
    ns = appsync.get_channel_namespace(apiId=good_api_id, name="default")["channelNamespace"]
    assert ns["codeHandlers"] == _VALID_HANDLER, ns["codeHandlers"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
