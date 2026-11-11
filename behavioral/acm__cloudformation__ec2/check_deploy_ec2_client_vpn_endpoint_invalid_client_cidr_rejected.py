"""deploy-ec2-client-vpn-endpoint-invalid-client-cidr-rejected."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-ec2-client-vpn-endpoint-invalid-client-cidr-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_VALID_CIDR = "10.199.0.0/22"
# ClientCidrBlock must be at least a /22; a /28 is well inside the documented minimum.
_INVALID_CIDR = "10.199.0.0/28"
_TAG_KEY = "sim2real-cvpn"
_REJECTED = (
    "Client cidr block must be at least a /22 range "
    "(Service: Ec2, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


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


def _template(tag_value: str, client_cidr: str, cert_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Endpoint": {
                "Type": "AWS::EC2::ClientVpnEndpoint",
                "Properties": {
                    "ClientCidrBlock": client_cidr,
                    "ServerCertificateArn": cert_arn,
                    "AuthenticationOptions": [{
                        "Type": "certificate-authentication",
                        "MutualAuthentication": {"ClientRootCertificateChainArn": cert_arn},
                    }],
                    "ConnectionLogOptions": {"Enabled": False},
                    "TagSpecifications": [{"ResourceType": "client-vpn-endpoint",
                                           "Tags": [{"Key": _TAG_KEY, "Value": tag_value}]}],
                },
            },
        },
        "Outputs": {"EndpointId": {"Value": {"Ref": "Endpoint"}}},
    })


def _tagged_endpoints(ec2, value: str) -> list[str]:
    return [e["ClientVpnEndpointId"] for e in paginate(
        ec2, "describe_client_vpn_endpoints", "ClientVpnEndpoints",
        Filters=[{"Name": f"tag:{_TAG_KEY}", "Values": [value]}])]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A Client VPN endpoint whose ClientCidrBlock is narrower than /22 fails and rolls back.

    EC2 refuses the /28 and lists no endpoint for it, while the same template at /22 deploys.
    """
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    cfn = ctx.client("cloudformation")
    good_stack = ctx.unique_name("sim2real-cfncvpncidr-good-")
    bad_stack = ctx.unique_name("sim2real-cfncvpncidr-bad-")

    cert_pem, key_pem = _self_signed_cert_pem(f"{good_stack}.example.com")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": good_stack}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    # Positive control: the same template, ClientCidrBlock given a valid /22.
    good_id = create_stack(ctx, cfn, good_stack, _template(good_stack, _VALID_CIDR, cert_arn))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_ep = stack_outputs(cfn, good_id)["EndpointId"]
    assert _tagged_endpoints(ec2, good_stack) == [good_ep], f"control endpoint {good_ep!r} not listed"
    cidr = ec2.describe_client_vpn_endpoints(
        ClientVpnEndpointIds=[good_ep])["ClientVpnEndpoints"][0]["ClientCidrBlock"]
    assert cidr == _VALID_CIDR, f"control ClientCidrBlock {cidr!r}"

    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_stack, _INVALID_CIDR, cert_arn))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Endpoint"), ctx.account)
    assert got == _REJECTED, f"Endpoint reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through EC2, by the tag the endpoint would carry, before the delete.
    listed = _tagged_endpoints(ec2, bad_stack)
    assert listed == [], f"endpoints tagged {bad_stack!r} after the rollback: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
