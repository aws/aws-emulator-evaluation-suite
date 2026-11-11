"""remove-listener-certificates-default-cert-forbidden."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "remove-listener-certificates-default-cert-forbidden"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveListenerCertificates on the default certificate fails with OperationNotPermitted "Default certificate
    cannot be removed" and keeps it, while removing a non-default certificate succeeds."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    default_cert_arn = _import_acm_cert(ctx, "sim2real-default.example.com")
    listener_arn = _create_https_listener(ctx, lb_arn, tg_arn, default_cert_arn)

    code, message = _error(
        lambda: elbv2.remove_listener_certificates(
            ListenerArn=listener_arn, Certificates=[{"CertificateArn": default_cert_arn}]
        )
    )
    # Real AWS raises this error as "OperationNotPermitted" (no "Exception" suffix on the wire code).
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected = "Default certificate cannot be removed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    certs = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert any(c["CertificateArn"] == default_cert_arn for c in certs), "default cert was unexpectedly removed"

    # Positive control: the identical API against a non-default certificate on the same
    # listener succeeds, proving the rejection above is specific to the default certificate
    # rather than a blanket failure of RemoveListenerCertificates on this wiring.
    extra_cert_arn = _import_acm_cert(ctx, "sim2real-extra.example.com")
    elbv2.add_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}])
    elbv2.remove_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}])
    after = {
        c["CertificateArn"] for c in elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    }
    assert extra_cert_arn not in after, "positive control: non-default cert removal did not take effect"
    assert default_cert_arn in after, "default cert should remain untouched by the positive control"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


_IN_USE = ("ResourceInUse", "ResourceInUseException", "DependencyViolation", "InvalidGroup.InUse")


def _safe_call(fn, attempts: int = 60, interval_s: float = 10.0):
    """Run a teardown delete: tolerate not-found, retry while a dependent resource still holds
    the target (a deleting listener or load balancer ENI), and raise anything else."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code.endswith("NotFoundException"):
                return
            if code not in _IN_USE or attempt == attempts - 1:
                raise
            time.sleep(interval_s)


def _default_vpc_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 AZs")
    return vpc_id, list(by_az.values())[:2]


def _new_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-elbv2-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real elbv2 behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: _delete_security_group_when_free(ec2, sg_id)))
    return sg_id


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-tg-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: _delete_target_group_when_free(elbv2, tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    waiter = elbv2.get_waiter("load_balancer_available")
    waiter.wait(LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return lb_arn


def _self_signed_cert(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _import_acm_cert(ctx, cn: str) -> str:
    key_pem, cert_pem = _self_signed_cert(cn)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_certificate(CertificateArn=arn)))
    return arn


def _create_https_listener(ctx, lb_arn, tg_arn, cert_arn, mutual_authentication=None):
    elbv2 = ctx.client("elbv2")
    kwargs = dict(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    if mutual_authentication:
        kwargs["MutualAuthentication"] = mutual_authentication
    resp = elbv2.create_listener(**kwargs)
    listener_arn = resp["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    return listener_arn


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
