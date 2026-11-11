"""add-listener-certificates-malformed-arn-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "add-listener-certificates-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates with a malformed certificate ARN fails with CertificateNotFound and the exact message
    and leaves only the default certificate, while adding a real ACM certificate to the same listener succeeds."""
    require_tools("openssl")
    cert_pem, key_pem = _generate_self_signed_pem(f"{ctx.unique_name('sim2real')}.example.com")

    acm = ctx.client("acm")
    default_cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-cert-")}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_while_in_use(lambda: acm.delete_certificate(CertificateArn=default_cert_arn)))

    elbv2 = ctx.client("elbv2")
    net = _create_vpc_with_subnets(ctx)
    lb_arn = _create_load_balancer(ctx, net)
    _wait_lb_active(ctx, lb_arn)
    tg_arn = _create_target_group(ctx, net["vpc_id"])

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": default_cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_listener(elbv2, listener_arn))

    code, message = _error_code(
        lambda: elbv2.add_listener_certificates(
            ListenerArn=listener_arn,
            Certificates=[{"CertificateArn": "not-a-certificate-arn-at-all"}],
        )
    )
    assert code == "CertificateNotFound", f"expected CertificateNotFound, got {code!r}"
    expected_message = "Certificate 'not-a-certificate-arn-at-all' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect-absent: only the original default certificate is on the listener
    certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert [c["CertificateArn"] for c in certs] == [default_cert_arn], (
        f"expected only {default_cert_arn!r} on the listener, got {certs!r}"
    )

    # positive control: a real, importable ACM certificate is added successfully
    cert2_pem, key2_pem = _generate_self_signed_pem(f"{ctx.unique_name('sim2real2')}.example.com")
    extra_cert_arn = acm.import_certificate(
        Certificate=cert2_pem,
        PrivateKey=key2_pem,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-cert2-")}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_while_in_use(lambda: acm.delete_certificate(CertificateArn=extra_cert_arn)))
    # Runs before the certificate delete: the listener must release the certificate first.
    ctx.on_cleanup(lambda: _delete_listener(elbv2, listener_arn))

    elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )
    certs_after = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert {c["CertificateArn"] for c in certs_after} == {default_cert_arn, extra_cert_arn}, (
        f"expected {{default={default_cert_arn!r}, extra={extra_cert_arn!r}}} on the listener, "
        f"got {certs_after!r}"
    )


def _generate_self_signed_pem(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True,
            capture_output=True,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _error_code(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx, az_count: int = 2) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16", TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][:az_count]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.83.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[
                _tag_spec("subnet", ctx.unique_name("sim2real-elbv2-subnet-"))
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_subnet_with_retry(ec2, sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _delete_subnet_with_retry(ec2, subnet_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _delete_vpc_with_retry(ec2, vpc_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_load_balancer(ctx, net: dict[str, Any]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lb-")
    lb_arn = elbv2.create_load_balancer(
        Name=name,
        Subnets=net["subnet_ids"],
        SecurityGroups=[net["sg_id"]],
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    return lb_arn


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180.0) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as err:
            if err.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 360.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(5)
    raise AssertionError("load balancer did not become active in time")


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_while_in_use(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _delete_listener(elbv2, listener_arn: str) -> None:
    """Delete the listener; ListenerNotFound means the other registered teardown already did."""
    try:
        elbv2.delete_listener(ListenerArn=listener_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ListenerNotFound":
            raise


def _retry_while_in_use(delete, timeout_s: float = 300.0) -> None:
    """Run a teardown delete, retrying while a just-deleted load balancer still holds the resource.

    DeleteLoadBalancer returns before ELB and ACM drop the listener's associations, so an in-use
    rejection is expected for a while.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("ResourceInUse", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
