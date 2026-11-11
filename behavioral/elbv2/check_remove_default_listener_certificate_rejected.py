"""remove-default-listener-certificate-rejected."""
from __future__ import annotations

import re
import time
from typing import Any

from behavioral_harness import tags

CHECK = "remove-default-listener-certificate-rejected"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveListenerCertificates on the listener's default certificate fails with OperationNotPermitted "Default
    certificate cannot be removed" and keeps it, while removing a non-default certificate succeeds."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _pick_two_subnets(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)
    tg_arn = _create_target_group(ctx, vpc_id)
    default_cert_arn = _import_self_signed_cert(ctx, "sim2real-def-neg")
    extra_cert_arn = _import_self_signed_cert(ctx, "sim2real-extra-neg")

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": default_cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )

    code, message = _error(
        lambda: elbv2.remove_listener_certificates(
            ListenerArn=listener_arn, Certificates=[{"CertificateArn": default_cert_arn}]
        )
    )
    # ELBv2's wire error code for this modeled exception omits the "Exception" suffix
    # that botocore's generated exception class name carries.
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected = "Default certificate cannot be removed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_present = {
        c["CertificateArn"]: c["IsDefault"]
        for c in elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    }
    assert still_present.get(default_cert_arn) is True, "default certificate was removed despite rejection"

    # Positive control: removing the non-default certificate on the same listener succeeds.
    elbv2.remove_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )
    after = {
        c["CertificateArn"]
        for c in elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    }
    assert extra_cert_arn not in after, f"expected {extra_cert_arn} removed, still present in {after}"
    assert default_cert_arn in after, f"expected default {default_cert_arn} to remain, got {after}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _retry_in_use(fn, attempts: int = 30, interval_s: float = 10.0):
    """Run a teardown delete, retrying while a just-deleted listener still holds the resource."""
    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceInUse", "ResourceInUseException") or attempt == attempts - 1:
                raise
            time.sleep(interval_s)


def _safe_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "", raw)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    cleaned = cleaned[:32].rstrip("-")
    return cleaned or "sim2real-fallback"


def _pick_two_subnets(ctx: Any):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("fewer than 2 AZs with subnets in shared network")
    return vpc_id, list(by_az.values())[:2]


def _create_alb(ctx: Any, subnet_ids) -> str:
    elbv2 = ctx.client("elbv2")
    name = _safe_name(ctx, "sim2real-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_lb_active(ctx: Any, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = last["State"]["Code"]
        if code == "active":
            return
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {last['State']}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never reached active, last state={last}")


def _create_target_group(ctx: Any, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = _safe_name(ctx, "sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=[{"Key": "Name", "Value": name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _retry_in_use(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _self_signed_leaf_pem(common_name: str):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _import_self_signed_cert(ctx: Any, common_name: str) -> str:
    cert_pem, key_pem = _self_signed_leaf_pem(common_name)
    acm = ctx.client("acm")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": common_name}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_in_use(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
