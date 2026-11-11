"""deploy-oauth2-credential-provider-cfn-provisions-and-tombstones."""
from __future__ import annotations

import json
import re
import secrets
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-oauth2-credential-provider-cfn-provisions-and-tombstones"
GROUP = "deploy"
SERVICES = ["bedrock-agentcore-control", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_GONE = ("ResourceNotFoundException", "CredentialProvider not found")
_ISSUER = "https://sim2real.example.com/oauth2"
_AUTHZ_ENDPOINT = "https://sim2real.example.com/oauth2/authorize"
_TOKEN_ENDPOINT = "https://sim2real.example.com/oauth2/token"


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _template(provider_name, client_id):
    """The client secret is a NoEcho parameter, never a literal in the template body."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ClientSecret": {"Type": "String", "NoEcho": True}},
        "Resources": {"Oauth2Provider": {
            "Type": "AWS::BedrockAgentCore::OAuth2CredentialProvider",
            "Properties": {
                "Name": provider_name,
                "CredentialProviderVendor": "CustomOauth2",
                "Oauth2ProviderConfigInput": {"CustomOauth2ProviderConfig": {
                    "ClientId": client_id,
                    "ClientSecret": {"Ref": "ClientSecret"},
                    "OauthDiscovery": {"AuthorizationServerMetadata": {
                        "Issuer": _ISSUER,
                        "AuthorizationEndpoint": _AUTHZ_ENDPOINT,
                        "TokenEndpoint": _TOKEN_ENDPOINT,
                    }},
                }},
            },
        }},
        "Outputs": {
            "ProviderArn": {"Value": {"Ref": "Oauth2Provider"}},
            "ProviderArnAtt": {
                "Value": {"Fn::GetAtt": ["Oauth2Provider", "CredentialProviderArn"]}
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed OAuth2CredentialProvider reads back through AgentCore's own API.

    Ref and the CredentialProviderArn GetAtt match the listed provider, its client secret is a
    Secrets Manager ARN, every templated input reads back, and the stack delete removes it.
    """
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    provider_name = _alnum_name(ctx, "sim2realcfnoauth")
    client_id = ctx.unique_name("sim2real-oauth-client-")

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-oauth2cp-"), _template(provider_name, client_id),
        Parameters=[{"ParameterKey": "ClientSecret", "ParameterValue": secrets.token_hex(24)}],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {_reasons(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    listed = [p["credentialProviderArn"]
              for p in paginate(control, "list_oauth2_credential_providers", "credentialProviders")
              if p["name"] == provider_name]
    assert listed == [out["ProviderArn"]], (
        f"ListOauth2CredentialProviders by name {provider_name!r}: {listed!r}; "
        f"Ref {out['ProviderArn']!r}"
    )
    got = control.get_oauth2_credential_provider(name=provider_name)
    got_ids = (got["name"], got["credentialProviderArn"], got["credentialProviderVendor"])
    want_ids = (provider_name, out["ProviderArn"], "CustomOauth2")
    assert (got_ids, out["ProviderArnAtt"]) == (want_ids, out["ProviderArn"]), (
        f"GetOauth2CredentialProvider {got_ids!r}, expected {want_ids!r}; "
        f"GetAtt CredentialProviderArn {out['ProviderArnAtt']!r}"
    )
    partition = stack_id.split(":")[1]
    secret_arn = re.compile(rf"arn:{partition}:secretsmanager:{re.escape(ctx.region)}:"
                            rf"{ctx.account}:secret:[a-zA-Z0-9-_/+=.@!]+")
    assert secret_arn.fullmatch(got["clientSecretArn"]["secretArn"]), (
        f"clientSecretArn {got['clientSecretArn']!r}"
    )
    config = got["oauth2ProviderConfigOutput"]["customOauth2ProviderConfig"]
    metadata = config["oauthDiscovery"]["authorizationServerMetadata"]
    got_cfg = (config["clientId"], metadata["issuer"], metadata["authorizationEndpoint"],
               metadata["tokenEndpoint"])
    want_cfg = (client_id, _ISSUER, _AUTHZ_ENDPOINT, _TOKEN_ENDPOINT)
    assert got_cfg == want_cfg, f"provider config {got_cfg!r}, expected {want_cfg!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: control.get_oauth2_credential_provider(name=provider_name), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
