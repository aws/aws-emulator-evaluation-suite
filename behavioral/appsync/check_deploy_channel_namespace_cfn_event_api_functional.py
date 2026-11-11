"""deploy-channel-namespace-cfn-event-api-functional."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-channel-namespace-cfn-event-api-functional"
GROUP = "server-side"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Event API ChannelNamespace reports the template's auth modes, accepts an HTTP
    publish to its channel, and is gone after the stack is deleted.
    """
    api_name = ctx.unique_name("sim2real-appsync-evt-")
    template = {
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
                    "Name": "default",
                    # Explicit overrides, so GetChannelNamespace has template values to reflect.
                    "SubscribeAuthModes": [{"AuthType": "API_KEY"}],
                    "PublishAuthModes": [{"AuthType": "API_KEY"}],
                },
            },
        },
        "Outputs": {"ApiId": {"Value": {"Fn::GetAtt": ["EvtApi", "ApiId"]}}},
    }

    stack_name, outputs = _deploy_stack(ctx, template, capabilities=[])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    api_id = outputs["ApiId"]

    appsync = ctx.client("appsync")
    ns = appsync.get_channel_namespace(apiId=api_id, name="default")["channelNamespace"]
    assert ns["name"] == "default"
    assert [m["authType"] for m in ns["subscribeAuthModes"]] == ["API_KEY"], ns
    assert [m["authType"] for m in ns["publishAuthModes"]] == ["API_KEY"], ns

    api = appsync.get_api(apiId=api_id)["api"]
    http_domain = api["dns"]["HTTP"]

    api_key = appsync.create_api_key(apiId=api_id, description="sim2real test key")["apiKey"]["id"]

    http_url, route_headers = ctx.endpoint_route(http_domain)
    status, payload = _http_post_json(
        f"{http_url}/event",
        {"content-type": "application/json", "x-api-key": api_key, **route_headers},
        {"channel": "default/testchannel", "events": [json.dumps({"hello": "world"})]},
        verify=ctx.http_verify,
    )
    assert status == 200, f"publish to deployed Event API failed: {status} {payload}"
    assert payload.get("failed") == []
    assert len(payload.get("successful", [])) == 1, f"unexpected publish result: {payload}"

    _delete_stack(ctx, stack_name)
    err = _error(lambda: appsync.get_channel_namespace(apiId=api_id, name="default"))
    assert err == ("NotFoundException", "API not found."), (
        f"expected the namespace to be gone after stack delete, got {err!r}"
    )




def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _deploy_stack(ctx: Any, template: dict, capabilities=None, params=None):
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-appsync-cfn-")
    kwargs = {
        "StackName": name,
        "TemplateBody": json.dumps(template),
        "Capabilities": capabilities if capabilities is not None else ["CAPABILITY_IAM"],
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if params:
        kwargs["Parameters"] = params
    cfn.create_stack(**kwargs)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    outputs_raw = cfn.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    outputs = {o["OutputKey"]: o["OutputValue"] for o in outputs_raw}
    return name, outputs


def _delete_stack(ctx: Any, name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_post_json(url: str, headers: dict, body_obj: dict, timeout: float = 20.0, *, verify):
    data = json.dumps(body_obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(verify)) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
