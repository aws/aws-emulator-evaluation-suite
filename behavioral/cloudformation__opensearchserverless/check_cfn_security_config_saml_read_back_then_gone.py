"""cfn-security-config-saml-read-back-then-gone."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-security-config-saml-read-back-then-gone"
GROUP = "deploy"
SERVICES = ["cloudformation", "opensearchserverless"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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


_SAML_METADATA = (
    '<?xml version="1.0"?>\n'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sim2real-behav.example.com/saml">\n'
    '  <IDPSSODescriptor WantAuthnRequestsSigned="false" '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
    '    <KeyDescriptor use="signing">\n'
    '      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n'
    '        <X509Data>\n'
    '          <X509Certificate>MIIDAzCCAeugAwIBAgIJAJ1234567890MA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNVBAMM'
    'D3NpbTJyZWFsLWJlaGF2MB4XDTIwMDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowGjEYMBYGA1UEAwwPc2ltMnJlYWwt'
    'YmVoYXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp9'
    '8C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56'
    'YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2dSWSKUY8RcU4iDmkJc'
    'YSzQ</X509Certificate>\n'
    '        </X509Data>\n'
    '      </KeyInfo>\n'
    '    </KeyDescriptor>\n'
    '    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://sim2real-behav.example.com/saml/sso"/>\n'
    '  </IDPSSODescriptor>\n'
    '</EntityDescriptor>'
)


def _short_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _pages(call, key, **kw):
    """Every item under ``key`` across all nextToken pages (the operation has no paginator)."""
    items, token = [], None
    while True:
        page = call(**kw, **({"nextToken": token} if token else {}))
        items += page[key]
        token = page.get("nextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::OpenSearchServerless::SecurityConfig of type saml carries the declared
    SAML metadata and session timeout at OpenSearch Serverless under the id its Ref returns, and
    deleting the stack removes it there too.
    """
    cfn = ctx.client("cloudformation")
    aoss = ctx.client("opensearchserverless")
    stack_name = ctx.unique_name("sim2real-behav-cfn-secconf-")
    config_name = _short_name(ctx, "sim2real-secconf")
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SecurityConfig": {
                "Type": "AWS::OpenSearchServerless::SecurityConfig",
                "Properties": {
                    "Name": config_name,
                    "Type": "saml",
                    "SamlOptions": {"Metadata": _SAML_METADATA, "SessionTimeout": 60},
                },
            },
        },
        "Outputs": {"ConfigRef": {"Value": {"Ref": "SecurityConfig"}}},
    })
    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    config_ref = stack_outputs(cfn, stack_id)["ConfigRef"]

    # Ref == the documented id format == the independent ListSecurityConfigs entry.
    expected_id = f"saml/{ctx.account}/{config_name}"
    listed = [c["id"] for c in _pages(aoss.list_security_configs, "securityConfigSummaries",
                                      type="saml")
              if c["id"] == expected_id]
    assert (config_ref, listed) == (expected_id, [expected_id]), (
        f"Ref {config_ref!r}, ListSecurityConfigs ids {listed!r}, expected {expected_id!r}"
    )
    detail = aoss.get_security_config(id=listed[0])["securityConfigDetail"]
    got = (detail["id"], detail["type"], detail["samlOptions"]["metadata"] == _SAML_METADATA,
           detail["samlOptions"].get("sessionTimeout"))
    assert got == (expected_id, "saml", True, 60), (
        f"(id, type, metadata round-trips, sessionTimeout) {got!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: aoss.get_security_config(id=expected_id))
    gone = ("ResourceNotFoundException", f"Security config with id: {expected_id} does not exist")
    expect_error(lambda: aoss.get_security_config(id=expected_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
