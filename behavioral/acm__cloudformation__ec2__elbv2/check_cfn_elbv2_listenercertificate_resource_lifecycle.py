"""cfn-elbv2-listenercertificate-resource-lifecycle."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-listenercertificate-resource-lifecycle"
GROUP = "cloudformation"
SERVICES = ["acm", "cloudformation", "ec2", "elbv2"]

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

_TAG_KEY = "sim2real-lc"


def _self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    """A fresh self-signed RSA certificate and its PEM-encoded key, for ACM import."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _import_cert(ctx, acm, common_name: str, tag_value: str) -> str:
    cert_pem, key_pem = _self_signed_cert(common_name)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": tag_value}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn


def _template(tag_value: str, cidr_prefix: str, listener_cert_arn) -> str:
    """VPC, two subnets, an internal ALB and an HTTPS listener on parameter CertAArn.

    ``listener_cert_arn`` (a value or None) adds a ListenerCertificate naming it.
    """
    t = [{"Key": _TAG_KEY, "Value": tag_value}]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": f"{cidr_prefix}.0.0/16",
                                                        "Tags": t}},
        "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.1.0/24",
            "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": t}},
        "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.2.0/24",
            "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]}, "Tags": t}},
        "AlbSg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "sim2real listener certificate", "VpcId": {"Ref": "Vpc"},
            "Tags": t}},
        "Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
            "Type": "application", "Scheme": "internal",
            "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
            "SecurityGroups": [{"Ref": "AlbSg"}], "Tags": t}},
        "Listener": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
            "LoadBalancerArn": {"Ref": "Alb"}, "Port": 443, "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-2016-08",
            "Certificates": [{"CertificateArn": {"Ref": "CertAArn"}}],
            "DefaultActions": [{"Type": "fixed-response", "FixedResponseConfig": {
                "StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"}}],
        }},
    }
    if listener_cert_arn is not None:
        resources["ListenerCert"] = {
            "Type": "AWS::ElasticLoadBalancingV2::ListenerCertificate",
            "Properties": {"ListenerArn": {"Ref": "Listener"},
                           "Certificates": [{"CertificateArn": listener_cert_arn}]},
        }
    return json.dumps({
        "Parameters": {"CertAArn": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {"AlbRef": {"Value": {"Ref": "Alb"}},
                    "ListenerRef": {"Value": {"Ref": "Listener"}}},
    })


def _listener_certs(elbv2, listener_arn: str) -> dict:
    return {c["CertificateArn"]: c["IsDefault"] for c in paginate(
        elbv2, "describe_listener_certificates", "Certificates", ListenerArn=listener_arn)}


def _listener(elbv2, alb_arn: str, listener_ref: str) -> dict:
    """The ALB's only listener, found by its load balancer (an independent read of the Ref)."""
    listeners = paginate(elbv2, "describe_listeners", "Listeners", LoadBalancerArn=alb_arn)
    assert [x["ListenerArn"] for x in listeners] == [listener_ref], (
        f"listeners of {alb_arn!r}: {[x['ListenerArn'] for x in listeners]!r}, Ref {listener_ref!r}"
    )
    return listeners[0]


# What EC2 answers for each network resource the stack created, once the stack delete removed it.
_EC2_GONE = {
    "AWS::EC2::VPC": ("describe_vpcs", "VpcIds", "InvalidVpcID.NotFound",
                      "The vpc ID '{}' does not exist"),
    "AWS::EC2::Subnet": ("describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound",
                         "The subnet ID '{}' does not exist"),
    "AWS::EC2::SecurityGroup": ("describe_security_groups", "GroupIds", "InvalidGroup.NotFound",
                                "The security group '{}' does not exist"),
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ListenerCertificate attaches a second certificate to an HTTPS listener.

    Dropping it in an update removes exactly that certificate from the live listener, which keeps
    its default certificate; the stack delete removes the listener and the network.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    stack = ctx.unique_name("sim2real-behav-lcstack-")
    cert_a = _import_cert(ctx, acm, f"{stack}-a.example.com", stack)
    cert_b = _import_cert(ctx, acm, f"{stack}-b.example.com", stack)
    params = [{"ParameterKey": "CertAArn", "ParameterValue": cert_a}]

    stack_id = create_stack(ctx, cfn, stack, _template(stack, "10.98", cert_b), Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    listener = _listener(elbv2, out["AlbRef"], out["ListenerRef"])
    listener_arn = listener["ListenerArn"]
    got = (listener["Port"], listener["Protocol"], listener["SslPolicy"])
    assert got == (443, "HTTPS", "ELBSecurityPolicy-2016-08"), f"listener reads {got!r}"
    certs = _listener_certs(elbv2, listener_arn)
    assert certs == {cert_a: True, cert_b: False}, (
        f"listener certificates {certs!r}: expected {cert_a!r} default and {cert_b!r} attached"
    )

    # Child before parent: the update drops only the ListenerCertificate.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, "10.98", None),
                     Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"ListenerCertificate-removing update ended {status!r}"
    certs = _listener_certs(elbv2, listener_arn)
    assert certs == {cert_a: True}, f"listener certificates after the update: {certs!r}"

    network = sorted(
        (r["ResourceType"], r["PhysicalResourceId"])
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
        if r["ResourceType"] in _EC2_GONE
    )
    delete_stack(cfn, stack_id)
    refused = ("ListenerNotFound", "One or more listeners not found")
    expect_error(lambda: elbv2.describe_listener_certificates(ListenerArn=listener_arn), *refused)
    for rtype, physical_id in network:
        op, param, code, message = _EC2_GONE[rtype]
        refused = (code, message.format(physical_id))
        expect_error(lambda: getattr(ec2, op)(**{param: [physical_id]}), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
