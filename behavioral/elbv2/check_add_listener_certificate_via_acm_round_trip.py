"""add-listener-certificate-via-acm-round-trip."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "add-listener-certificate-via-acm-round-trip"
GROUP = "cross-service"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates attaches a non-default ACM certificate to an HTTPS listener
    alongside the default certificate, and RemoveListenerCertificates detaches it again."""
    vpc_id, subnet_ids, sg_id = _create_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    acm = ctx.client("acm")

    cert_a_pem, key_a_pem = _generate_self_signed_pem(ctx, "sim2real-a.example.com")
    cert_b_pem, key_b_pem = _generate_self_signed_pem(ctx, "sim2real-b.example.com")

    arn_a = acm.import_certificate(
        Certificate=cert_a_pem, PrivateKey=key_a_pem, Tags=[_tag_kv(ctx, "cert-a")]
    )["CertificateArn"]
    arn_b = acm.import_certificate(
        Certificate=cert_b_pem, PrivateKey=key_b_pem, Tags=[_tag_kv(ctx, "cert-b")]
    )["CertificateArn"]

    lb = _create_alb_no_cleanup(ctx, subnet_ids, sg_id)
    lb_arn = lb["LoadBalancerArn"]
    tg = _create_target_group(ctx, vpc_id)

    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": arn_a}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]

    # Register cert cleanups now, then the load balancer cleanup LAST so LIFO teardown
    # deletes the load balancer (and its listener) before we try to delete the certs.
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=arn_a)))
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=arn_b)))
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))

    before = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    before_arns = {c["CertificateArn"] for c in before}
    assert arn_a in before_arns, before

    elbv2.add_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": arn_b}])

    after_add = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    by_arn = {c["CertificateArn"]: c for c in after_add}
    assert arn_a in by_arn and arn_b in by_arn, by_arn
    assert by_arn[arn_a].get("IsDefault") is True, by_arn[arn_a]
    assert by_arn[arn_b].get("IsDefault") is not True, by_arn[arn_b]

    elbv2.remove_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": arn_b}])

    after_remove = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    after_remove_arns = {c["CertificateArn"] for c in after_remove}
    assert arn_b not in after_remove_arns, after_remove_arns
    assert arn_a in after_remove_arns, after_remove_arns


_GONE = {"ResourceNotFoundException", "LoadBalancerNotFound", "TargetGroupNotFound",
         "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}
_BUSY = {"ResourceInUseException", "ResourceInUse"}


def _safe(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries while a dependency is still being released."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _GONE:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tag_kv(ctx, suffix):
    return {"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{suffix}-")}


def _tag_spec(ctx, resource_type, suffix):
    return {"ResourceType": resource_type, "Tags": [_tag_kv(ctx, suffix)]}


def _create_vpc_and_subnets(ctx):
    """Use the provided network's VPC when it has subnets in >=2 AZs (no VPC quota cost);
    otherwise create a dedicated VPC with two subnets."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            subnet_ids = list(by_az.values())[:2]
            sg_id = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )["SecurityGroups"][0]["GroupId"]
            return vpc_id, subnet_ids, sg_id

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError(f"fewer than 2 available availability zones in {ctx.region}: {azs}")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet", f"subnet-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_alb_no_cleanup(ctx, subnet_ids, sg_id, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        Tags=[_tag_kv(ctx, "lb")],
    )
    return resp["LoadBalancers"][0]


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {
        "Name": name,
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": vpc_id,
        "TargetType": "ip",
        "Tags": [_tag_kv(ctx, "tg")],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


def _generate_self_signed_pem(ctx, common_name):
    tmpdir = tempfile.mkdtemp(prefix="sim2real-elbv2-cert-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    key_path = os.path.join(tmpdir, f"{common_name}-key.pem")
    cert_path = os.path.join(tmpdir, f"{common_name}-cert.pem")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
        "-out", cert_path, "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
    ]
    require_tools("openssl")
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
    except subprocess.CalledProcessError as e:
        raise AssertionError(f"openssl failed to generate a self-signed cert: {e.stderr!r}")
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()
    return cert_pem, key_pem


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
