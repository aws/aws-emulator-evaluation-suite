"""create-listener-unknown-ssl-policy-name-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-listener-unknown-ssl-policy-name-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An HTTPS listener naming a nonexistent SslPolicy is rejected with SSLPolicyNotFound and no
    listener is created; the same load balancer then accepts a built-in SSL policy name."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    elbv2 = ctx.client("elbv2")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    tag_kv = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]
    subnet_a, subnet_b, _vpc_id = _two_az_subnets_create_or_adopt(ctx, ec2, tag_kv)

    cert_pem, key_pem = _self_signed_cert(ctx)
    cert_name = _short_name(ctx, "sim2real-sslpol-cert-", 128)
    cert_arn = iam.upload_server_certificate(
        ServerCertificateName=cert_name, CertificateBody=cert_pem, PrivateKey=key_pem, Tags=tag_kv
    )["ServerCertificateMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: _retry_while_in_use(lambda: iam.delete_server_certificate(ServerCertificateName=cert_name))
        )
    )

    lb_name = _short_name(ctx, "sim2real-sslpol-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=tag_kv
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )

    fixed_response_action = [
        {"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"}}
    ]

    code, message = _error_code(
        lambda: elbv2.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTPS",
            Port=443,
            Certificates=[{"CertificateArn": cert_arn}],
            SslPolicy="ELBSecurityPolicy-Nonexistent-9999",
            DefaultActions=fixed_response_action,
            Tags=tag_kv,
        )
    )
    assert code == "SSLPolicyNotFound", f"expected SSLPolicyNotFound for an unknown SslPolicy name, got {code!r}"
    expected_message = "SSL policy 'ELBSecurityPolicy-Nonexistent-9999' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    listeners_after_reject = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert all(listener["Port"] != 443 for listener in listeners_after_reject), (
        f"expected no port-443 listener after the rejected create_listener call, found one in "
        f"{[li['ListenerArn'] for li in listeners_after_reject]}"
    )

    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
        DefaultActions=fixed_response_action,
        Tags=tag_kv,
    )
    listener_arn = resp["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    actual_policy = resp["Listeners"][0]["SslPolicy"]
    assert actual_policy == "ELBSecurityPolicy-2016-08", (
        f"expected SslPolicy 'ELBSecurityPolicy-2016-08' on the positive-control listener, got {actual_policy!r}"
    )
    listeners_after_ok = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    assert any(listener["Port"] == 443 for listener in listeners_after_ok), (
        f"expected an independent read to show a port-443 listener after the accepted create_listener "
        f"call, found ports {[li['Port'] for li in listeners_after_ok]}"
    )


# ===== helpers =====


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must not be turned into a
    falsy sentinel that reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _two_az_subnets_create_or_adopt(ctx, ec2, tag_kv: list[dict[str, str]]) -> tuple[str, str, str]:
    """Adopt the shared network's subnets across >=2 AZs if one exists; otherwise create a
    fresh VPC with two subnets, since a freshly provisioned account may have no shared network."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            ids = list(by_az.values())
            return ids[0], ids[1], vpc_id

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=tag_kv + [{"Key": "Name", "Value": ctx.unique_name("sim2real-sslpol-vpc-")}])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region has fewer than 2 available Availability Zones ({len(azs)}) to place subnets in")
    subnet_ids = []
    for i in range(2):
        az = azs[i]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _ignore_not_found(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.create_tags(Resources=[sid], Tags=tag_kv)
        subnet_ids.append(sid)
    return subnet_ids[0], subnet_ids[1], vpc_id


def _self_signed_cert(ctx) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        cn = ctx.unique_name("sim2real-sslpol")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "1", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path), "-subj", f"/CN={cn}.example.com",
            ],
            check=True, capture_output=True,
        )
        return cert_path.read_text(), key_path.read_text()


# Teardown waits (bounded) for AWS-managed ENIs to leave: a load balancer, endpoint, cluster or
# instance in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Retry that inside one window shared
# by all of a check's network deletes, then raise naming the ENIs still attached.
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


def _retry_while_in_use(delete: Callable[[], Any], timeout_s: float = 300.0) -> None:
    """Run a teardown delete, retrying while a just-deleted load balancer still holds the resource.

    DeleteLoadBalancer returns before the listener releases its IAM server certificate, so a
    DeleteConflict is expected for a while.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("DeleteConflict", "ResourceInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
