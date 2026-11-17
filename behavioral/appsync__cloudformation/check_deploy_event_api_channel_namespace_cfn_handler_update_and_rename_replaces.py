"""deploy-event-api-channel-namespace-cfn-handler-update-and-rename-replaces."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-event-api-channel-namespace-cfn-handler-update-and-rename-replaces"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


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


def _delete_stack(cfn, stack_id, timeout_s=300.0):
    """Delete the stack by id and wait for ``DELETE_COMPLETE``; a ``DELETE_FAILED`` raises."""
    cfn.delete_stack(StackName=stack_id)
    status = _poll_stack(cfn, stack_id, timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {_fail_reasons(cfn, stack_id)}")


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _publish(url, headers, channel, events, verify):
    """POST ``events`` (JSON-encodable dicts) to the Event API's HTTP ``/event`` publish path."""
    body = json.dumps({"channel": channel, "events": [json.dumps(e) for e in events]}).encode()
    req = urllib.request.Request(url, data=body, headers={**headers, "content-type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20.0, context=_ssl_context(verify)) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _not_found(fn):
    """``(code, message)`` of the ``ClientError`` ``fn()`` raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NotFoundException, call succeeded with {result!r}")


# Handler v1 lets through only events whose payload carries "ok": true; handler v2 switches the
# required field to "ready", so a publish that passed under v1 is rejected under v2.
_HANDLER_V1 = (
    "export function onPublish(ctx) {\n"
    "  return ctx.events.map((event) => {\n"
    "    if (event.payload && event.payload.ok === true) {\n"
    "      return event;\n"
    "    }\n"
    "    return { ...event, error: 'payload.ok must be true' };\n"
    "  });\n"
    "}\n"
    "export function onSubscribe(ctx) {\n"
    "}\n"
)
_HANDLER_V2 = (
    "export function onPublish(ctx) {\n"
    "  return ctx.events.map((event) => {\n"
    "    if (event.payload && event.payload.ready === true) {\n"
    "      return event;\n"
    "    }\n"
    "    return { ...event, error: 'payload.ready must be true' };\n"
    "  });\n"
    "}\n"
    "export function onSubscribe(ctx) {\n"
    "}\n"
)

_NS_GONE = ("NotFoundException", "API not found.")
_CHANNEL_GONE = ("NotFoundException", "Channel namespace not found.")


def _template(api_name, owner_contact, api_tag_value, ns_name, handler, ns_tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EvtApi": {
                "Type": "AWS::AppSync::Api",
                "Properties": {
                    "Name": api_name,
                    "OwnerContact": owner_contact,
                    "Tags": [{"Key": "sim2real-api-tag", "Value": api_tag_value}],
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
                    "SubscribeAuthModes": [{"AuthType": "API_KEY"}],
                    "PublishAuthModes": [{"AuthType": "API_KEY"}],
                    "CodeHandlers": handler,
                    "Tags": [{"Key": "sim2real-ns-tag", "Value": ns_tag_value}],
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Fn::GetAtt": ["EvtApi", "ApiId"]}},
            "ApiArn": {"Value": {"Fn::GetAtt": ["EvtApi", "ApiArn"]}},
            "NamespaceArn": {"Value": {"Ref": "Namespace"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane",
      "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN Event API and ChannelNamespace serve publishes through their deployed JS handler.

    OwnerContact, Tags and the handler update in place without a new ApiId or ChannelNamespaceArn;
    renaming the namespace replaces it, and deleting the stack leaves neither behind.
    """
    cfn = ctx.client("cloudformation")
    appsync = ctx.client("appsync")
    stack_name = ctx.unique_name("sim2real-appsync-evtns-")
    api_name = ctx.unique_name("sim2real-appsync-evtns-api-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(api_name, "Owner-Team-v1", "v1", "default", _HANDLER_V1, "v1"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _poll_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}: {_fail_reasons(cfn, stack_id)}"
    out = {o["OutputKey"]: o["OutputValue"]
           for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    api_id, api_arn, ns_arn_1 = out["ApiId"], out["ApiArn"], out["NamespaceArn"]

    api = appsync.get_api(apiId=api_id)["api"]
    assert api["ownerContact"] == "Owner-Team-v1", api
    assert api["apiArn"] == api_arn, (api["apiArn"], api_arn)
    api_tags = appsync.list_tags_for_resource(resourceArn=api_arn)["tags"]
    assert api_tags.get("sim2real-api-tag") == "v1", api_tags

    ns = appsync.get_channel_namespace(apiId=api_id, name="default")["channelNamespace"]
    assert ns["codeHandlers"] == _HANDLER_V1, ns["codeHandlers"]
    assert [m["authType"] for m in ns["subscribeAuthModes"]] == ["API_KEY"], ns
    assert [m["authType"] for m in ns["publishAuthModes"]] == ["API_KEY"], ns
    assert ns["channelNamespaceArn"] == ns_arn_1, (ns["channelNamespaceArn"], ns_arn_1)
    ns_tags = appsync.list_tags_for_resource(resourceArn=ns_arn_1)["tags"]
    assert ns_tags.get("sim2real-ns-tag") == "v1", ns_tags

    api_key = appsync.create_api_key(apiId=api_id, description="sim2real-evtns-key")["apiKey"]["id"]
    http_url, route_headers = ctx.endpoint_route(api["dns"]["HTTP"])
    headers = {"x-api-key": api_key, **route_headers}
    status, payload = _publish(
        f"{http_url}/event", headers, "default/room",
        [{"ok": True, "turn": 1}, {"ok": False, "turn": 2}], ctx.http_verify,
    )
    assert status == 200, (status, payload)
    assert len(payload["successful"]) == 1 and len(payload["failed"]) == 1, payload
    assert (payload["failed"][0]["code"], payload["failed"][0]["message"]) == (
        "CustomError", "payload.ok must be true"
    ), payload

    # In-place update: handler, OwnerContact and both resources' Tags change; Name does not.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(api_name, "Owner-Team-v2", "v2", "default", _HANDLER_V2, "v2"),
    )
    status = _poll_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update ended {status!r}: {_fail_reasons(cfn, stack_id)}"
    out2 = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert (out2["ApiId"], out2["ApiArn"], out2["NamespaceArn"]) == (api_id, api_arn, ns_arn_1), (
        "an in-place update must keep the same Api and ChannelNamespace identities", out2
    )

    api = appsync.get_api(apiId=api_id)["api"]
    assert api["ownerContact"] == "Owner-Team-v2", api
    api_tags = appsync.list_tags_for_resource(resourceArn=api_arn)["tags"]
    assert api_tags.get("sim2real-api-tag") == "v2", api_tags
    ns = appsync.get_channel_namespace(apiId=api_id, name="default")["channelNamespace"]
    assert ns["codeHandlers"] == _HANDLER_V2, ns["codeHandlers"]
    ns_tags = appsync.list_tags_for_resource(resourceArn=ns_arn_1)["tags"]
    assert ns_tags.get("sim2real-ns-tag") == "v2", ns_tags

    status, payload = _publish(
        f"{http_url}/event", headers, "default/room",
        [{"ok": True, "turn": 3}, {"ready": True, "turn": 4}], ctx.http_verify,
    )
    assert status == 200, (status, payload)
    assert len(payload["successful"]) == 1 and len(payload["failed"]) == 1, payload
    assert (payload["failed"][0]["code"], payload["failed"][0]["message"]) == (
        "CustomError", "payload.ready must be true"
    ), payload

    # Name is create-only: renaming the namespace replaces it rather than updating it in place.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(api_name, "Owner-Team-v2", "v2", "renamed", _HANDLER_V2, "v2"),
    )
    status = _poll_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}: {_fail_reasons(cfn, stack_id)}"
    out3 = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert out3["ApiId"] == api_id, "the Api itself must not be replaced by the rename"
    ns_arn_2 = out3["NamespaceArn"]
    assert ns_arn_2 != ns_arn_1, "renaming a create-only Name must replace the ChannelNamespace"

    got = _not_found(lambda: appsync.get_channel_namespace(apiId=api_id, name="default"))
    assert got == _CHANNEL_GONE, got
    renamed = appsync.get_channel_namespace(apiId=api_id, name="renamed")["channelNamespace"]
    assert renamed["channelNamespaceArn"] == ns_arn_2, renamed
    assert renamed["codeHandlers"] == _HANDLER_V2, renamed["codeHandlers"]

    status, payload = _publish(
        f"{http_url}/event", headers, "renamed/room", [{"ready": True, "turn": 5}], ctx.http_verify,
    )
    assert status == 200, (status, payload)
    assert payload["failed"] == [], payload
    assert [s["index"] for s in payload["successful"]] == [0], payload

    _delete_stack(cfn, stack_id)
    got = _not_found(lambda: appsync.get_channel_namespace(apiId=api_id, name="renamed"))
    assert got == _NS_GONE, got
    got = _not_found(lambda: appsync.get_api(apiId=api_id))
    assert got == _NS_GONE, got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
