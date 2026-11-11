"""deploy-ec2-client-vpn-endpoint-family-round-trip-and-delete."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-ec2-client-vpn-endpoint-family-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["acm", "cloudformation", "ec2"]

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

_VPC_CIDR = "10.96.0.0/16"
_CLIENT_CIDR = "10.199.0.0/22"
_AUTH_CIDR = "10.96.1.0/24"
_TAG_KEY = "sim2real-cvpn"


def _self_signed_cert_pem(common_name: str) -> tuple[bytes, bytes]:
    """A per-run self-signed CA cert/key pair from the openssl CLI."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
             "-keyout", key_path, "-out", cert_path, "-days", "2",
             "-subj", f"/CN={common_name}",
             "-addext", "basicConstraints=critical,CA:true",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"],
            check=True, capture_output=True, timeout=30,
        )
        with open(key_path, "rb") as f:
            key_pem = f.read()
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
    return cert_pem, key_pem


def _template(tag_value: str, cert_arn: str, with_rule: bool = True) -> str:
    t = [{"Key": _TAG_KEY, "Value": tag_value}]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
        "Endpoint": {
            "Type": "AWS::EC2::ClientVpnEndpoint",
            "Properties": {
                "ClientCidrBlock": _CLIENT_CIDR,
                "ServerCertificateArn": cert_arn,
                "AuthenticationOptions": [{
                    "Type": "certificate-authentication",
                    "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
                }],
                "ConnectionLogOptions": {"Enabled": False},
                "VpcId": {"Ref": "Vpc"},
                "TagSpecifications": [{"ResourceType": "client-vpn-endpoint", "Tags": t}],
            },
        },
    }
    outputs = {"VpcId": {"Value": {"Ref": "Vpc"}}, "EndpointId": {"Value": {"Ref": "Endpoint"}}}
    if with_rule:
        resources["AuthRule"] = {
            "Type": "AWS::EC2::ClientVpnAuthorizationRule",
            "Properties": {"ClientVpnEndpointId": {"Ref": "Endpoint"},
                           "TargetNetworkCidr": _AUTH_CIDR, "AuthorizeAllGroups": True},
        }
        outputs["AuthRuleRef"] = {"Value": {"Ref": "AuthRule"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(tag_list) -> dict:
    return {t["Key"]: t["Value"] for t in tag_list or [] if t["Key"] == _TAG_KEY}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Client VPN endpoint and authorization rule read back through EC2.

    Their templated properties, tags and Refs match; an update dropping the rule removes it from the
    live endpoint, and the stack delete removes the endpoint and its VPC.
    """
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfncvpn-")

    cert_pem, key_pem = _self_signed_cert_pem(f"{stack}.example.com")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": stack}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    stack_id = create_stack(ctx, cfn, stack, _template(stack, cert_arn))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    vpc_id, ep_id = out["VpcId"], out["EndpointId"]

    # Ref against an independent read: the endpoints carrying this run's tag.
    eps = paginate(ec2, "describe_client_vpn_endpoints", "ClientVpnEndpoints",
                   Filters=[{"Name": f"tag:{_TAG_KEY}", "Values": [stack]}])
    assert [e["ClientVpnEndpointId"] for e in eps] == [ep_id], (
        f"endpoints tagged {stack!r}: {[e['ClientVpnEndpointId'] for e in eps]!r}, Ref {ep_id!r}"
    )
    ep = eps[0]
    got = (ep["VpcId"], ep["ClientCidrBlock"], ep["ServerCertificateArn"],
           ep["AuthenticationOptions"], ep["ConnectionLogOptions"], _own_tags(ep.get("Tags")),
           ep["Status"]["Code"])
    want = (vpc_id, _CLIENT_CIDR, cert_arn,
            [{"Type": "certificate-authentication",
              "MutualAuthentication": {"ClientRootCertificateChain": cert_arn}}],
            {"Enabled": False, "IncludeAuthorizationPolicyContext": False}, {_TAG_KEY: stack},
            "pending-associate")
    assert got == want, f"endpoint reads {got!r}, expected {want!r}"
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert (vpc["CidrBlock"], _own_tags(vpc.get("Tags"))) == (_VPC_CIDR, {_TAG_KEY: stack}), (
        f"VPC reads {vpc['CidrBlock']!r} {vpc.get('Tags')!r}"
    )

    # The rule's Ref is CloudFormation's id: base64 of endpoint|cidr|group (no group here).
    want_ref = base64.b64encode(f"{ep_id}|{_AUTH_CIDR}|".encode()).decode()
    assert out["AuthRuleRef"] == want_ref, f"AuthorizationRule Ref {out['AuthRuleRef']!r}"
    rules = paginate(ec2, "describe_client_vpn_authorization_rules", "AuthorizationRules",
                     ClientVpnEndpointId=ep_id)
    got = [(r["DestinationCidr"], r["AccessAll"], r["Status"]["Code"]) for r in rules]
    assert got == [(_AUTH_CIDR, True, "active")], f"authorization rules {got!r}"

    # Child before parent: the update drops only the rule; the same endpoint lists none.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, cert_arn, with_rule=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"rule-removing update ended {status!r}"
    rules = paginate(ec2, "describe_client_vpn_authorization_rules", "AuthorizationRules",
                     ClientVpnEndpointId=ep_id)
    assert rules == [], f"authorization rules on the live endpoint after the update: {rules!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[ep_id]))
    refused = ("InvalidClientVpnEndpointId.NotFound", f"Endpoint {ep_id} does not exist")
    expect_error(lambda: ec2.describe_client_vpn_endpoints(ClientVpnEndpointIds=[ep_id]), *refused)
    refused = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
