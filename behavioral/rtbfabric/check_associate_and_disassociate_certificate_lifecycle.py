"""associate-and-disassociate-certificate-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "associate-and-disassociate-certificate-lifecycle"
GROUP = "lifecycle"
SERVICES = ["rtbfabric"]

# Create refusals that ask for a retry: a just-created service-linked role still propagating, and
# a transient service failure.
_CREATE_RETRY = (
    ("AccessDeniedException", "Unable to assume the service linked role. Please verify that RTBFabric "
     "service linked role exists and retry."),
    ("400", "Unable to complete request. Please try again, or contact AWS Support if the issue persists."),
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After an INTERNAL responder gateway reaches ACTIVE, AssociateCertificate on it and
    CreateResponderGateway for an EXTERNAL managed-endpoint gateway on a non-allowlisted domain are
    each rejected with a specific error and leave no new resource behind.
    """
    require_tools("openssl")

    acm = ctx.client("acm")
    cert_arn = _import_self_signed_certificate(ctx, acm)

    rtb = ctx.client("rtbfabric")
    _ensure_service_linked_role(ctx)
    network = _create_network(ctx)

    # Positive control: an ordinary (INTERNAL) responder gateway reaches ACTIVE, proving the
    # account and credentials are otherwise healthy for rtbfabric before either refusal below.
    responder_gw = _create_responder_gateway(ctx, network)
    _wait_responder_active(ctx, responder_gw)

    # Real AWS's own reconciliation of the gateway can still be settling for a short window
    # after GetResponderGateway first reports ACTIVE, during which AssociateCertificate answers
    # ConflictException ("currently being modified by another operation"); retry through it to
    # reach the real, stable answer.
    code, message = _client_error(
        lambda: _retry_conflict(
            lambda: rtb.associate_certificate(
                gatewayId=responder_gw, acmCertificateArn=cert_arn, clientToken=ctx.unique_name("tok-")
            ),
            timeout_s=120.0,
            interval_s=5.0,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException associating a certificate on an INTERNAL gateway, got {code}"
    )
    expected_message = "Certificate association is only supported for EXTERNAL gatewayType"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    before = _responder_gateway_ids(rtb)
    ext_domain = f"{ctx.unique_name('sim2real-rtbfabric-ext-')}.example.com"
    code2, message2 = _client_error(lambda: _create_external_gateway(ctx, rtb, network, ext_domain))
    assert code2 == "ValidationException", (
        f"expected ValidationException creating an EXTERNAL gateway with an un-allowlisted domain, got {code2}"
    )
    expected_message2 = f"Domain name '{ext_domain}' for managed endpoint not allowlisted."
    assert message2 == expected_message2, f"expected {expected_message2!r}, got {message2!r}"
    created = _gateways_in_vpc(rtb, _responder_gateway_ids(rtb) - before, network["vpc_id"])
    assert not created, (
        f"expected no gateway to have been created by the refused request, found {sorted(created)} "
        f"in the check's VPC"
    )

    # Delete the INTERNAL gateway in-body and wait it out, so its ENIs leave before network teardown.
    _delete_responder_gateway_blocking(rtb, responder_gw)


# ===== helpers (self-contained) =====
def _responder_gateway_ids(rtb) -> set:
    """Every responder gateway id the account lists, across all pages."""
    return {
        gid
        for page in rtb.get_paginator("list_responder_gateways").paginate()
        for gid in page.get("gatewayIds", [])
    }


def _gateways_in_vpc(rtb, gateway_ids, vpc_id) -> set:
    """The ids among *gateway_ids* whose gateway sits in *vpc_id*; one deleted meanwhile is not."""
    found = set()
    for gid in gateway_ids:
        try:
            gateway = rtb.get_responder_gateway(gatewayId=gid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            continue
        if gateway.get("vpcId") == vpc_id:
            found.add(gid)
    return found


def _ensure_service_linked_role(ctx):
    """Create the RTB Fabric service-linked role that gateway creation assumes; an account that
    already holds it answers InvalidInput, which is the only tolerated refusal."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="rtbfabric.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _import_self_signed_certificate(ctx, acm):
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "2",
                "-subj",
                "/CN=sim2real-rtbfabric-test.example.com",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    imported = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rtbfabric-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.99.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=2.0,
    )
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.99.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real rtbfabric behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _create_responder_gateway(ctx, network, port=8443, protocol="HTTPS"):
    rtb = ctx.client("rtbfabric")
    domain_name = f"{ctx.unique_name('sim2real-rtbfabric-')}.example.com"
    token = ctx.unique_name("tok-")
    resp = _create_retrying(lambda: rtb.create_responder_gateway(
        vpcId=network["vpc_id"],
        subnetIds=[network["subnet_id"]],
        securityGroupIds=[network["sg_id"]],
        port=port,
        protocol=protocol,
        domainName=domain_name,
        clientToken=token,
    ))
    gateway_id = resp["gatewayId"]
    ctx.on_cleanup(lambda: _delete_responder_gateway_blocking(rtb, gateway_id))
    return gateway_id


def _create_retrying(create, timeout_s=180.0):
    """Call a gateway create (it carries a clientToken, so a repeat is idempotent), retrying every
    5 s on the _CREATE_RETRY refusals until timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return create()
        except ClientError as exc:
            error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            if error not in _CREATE_RETRY or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _delete_responder_gateway_blocking(rtb, gateway_id, timeout_s=1200.0):
    """Delete a responder gateway and wait until it reads DELETED or not-found, so its ENIs have
    left before the network under it is torn down. DeleteResponderGateway refuses a gateway that
    is still settling (ConflictException), so the delete is retried through that window. Safe to
    call twice: a gateway that is already gone returns at once."""

    def gone():
        try:
            return rtb.get_responder_gateway(gatewayId=gateway_id)["status"] == "DELETED"
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise

    deadline = time.monotonic() + timeout_s
    while not gone():
        try:
            rtb.delete_responder_gateway(gatewayId=gateway_id)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(15.0)
    while not gone():
        if time.monotonic() >= deadline:
            raise AssertionError(f"responder gateway {gateway_id} not deleted within {timeout_s}s")
        time.sleep(15.0)


def _create_external_gateway(ctx, rtb, network, domain_name):
    # EXTERNAL + a managed endpoint is the only gateway shape that supports certificate
    # association at all (an INTERNAL gateway rejects AssociateCertificate outright, as the
    # first assertion shows). Real AWS validates the domain-allowlist entitlement before it ever looks at
    # whether the referenced auto scaling group or role exist, so a syntactically valid but
    # nonexistent auto scaling group / role surfaces the SAME domain-allowlisting refusal as a
    # fully provisioned one would, without provisioning either. This never
    # returns a gatewayId to clean up: CreateResponderGateway rejects the request before creating
    # anything.
    account = ctx.client("sts").get_caller_identity()["Account"]
    return rtb.create_responder_gateway(
        vpcId=network["vpc_id"],
        subnetIds=[network["subnet_id"]],
        securityGroupIds=[network["sg_id"]],
        port=8443,
        protocol="HTTPS",
        domainName=domain_name,
        gatewayType="EXTERNAL",
        managedEndpointConfiguration={
            "autoScalingGroups": {
                "autoScalingGroupNames": [ctx.unique_name("sim2real-asg-")],
                "roleArn": f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-mep-')}",
            }
        },
        clientToken=ctx.unique_name("tok-"),
    )


def _wait_responder_active(ctx, gateway_id, timeout_s=900.0):
    rtb = ctx.client("rtbfabric")
    status = _poll_until(
        lambda: rtb.get_responder_gateway(gatewayId=gateway_id)["status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    assert status == "ACTIVE", f"responder gateway settled in {status}, expected ACTIVE"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_conflict(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC
# while the check passes. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached; every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes and fits
# the suite's 900 s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
