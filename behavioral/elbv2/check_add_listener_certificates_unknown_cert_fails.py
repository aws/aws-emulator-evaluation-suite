"""add-listener-certificates-unknown-cert-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "add-listener-certificates-unknown-cert-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates with a nonexistent ACM ARN fails with CertificateNotFound and the exact message and
    leaves only the default certificate, while adding a real certificate to the same listener succeeds."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    default_cert_arn = _import_acm_cert(ctx, "sim2real-default.example.com", lb_arn)
    listener_arn = _create_https_listener(ctx, lb_arn, tg_arn, default_cert_arn)

    bogus_arn = (
        f"arn:aws:acm:{ctx.region}:111122223333:certificate/"
        "00000000-0000-0000-0000-000000000000"
    )
    code, message = _error_code(
        lambda: elbv2.add_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": bogus_arn}])
    )
    # Real AWS raises this error as "CertificateNotFound" (no "Exception" suffix on the wire code).
    assert code == "CertificateNotFound", f"expected CertificateNotFound, got {code}"
    expected_message = f"Certificate '{bogus_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    certs_after_rejection = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert len(certs_after_rejection) == 1, (
        f"expected the rejected AddListenerCertificates call to leave no trace, "
        f"got {certs_after_rejection!r}"
    )
    assert certs_after_rejection[0]["CertificateArn"] == default_cert_arn
    assert all(c["CertificateArn"] != bogus_arn for c in certs_after_rejection)

    # Positive control: an otherwise-identical AddListenerCertificates call with a real ACM
    # ARN must succeed, so this check cannot pass merely because the operation rejects every call.
    extra_cert_arn = _import_acm_cert(ctx, "sim2real-extra.example.com", lb_arn)
    elbv2.add_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}])
    certs_after_success = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert {c["CertificateArn"] for c in certs_after_success} == {default_cert_arn, extra_cert_arn}, (
        f"positive control did not add the real certificate: {certs_after_success!r}"
    )


def _error_code(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


# A load balancer deletes asynchronously: DeleteLoadBalancer returns while the listener still holds
# its certificates and target group and its ENIs still sit in the security group. Each teardown
# delete therefore retries the in-use rejection every 2 s to one deadline shared by all of the
# check's teardowns (inside the suite's 900 s cleanup budget) and re-raises a final failure; a
# not-found means the resource is already gone.
_IN_USE_CODES = ("ResourceInUse", "ResourceInUseException", "DependencyViolation")
_GONE_CODES = (
    "LoadBalancerNotFound", "TargetGroupNotFound", "ResourceNotFoundException", "InvalidGroup.NotFound"
)
_TEARDOWN_S = 840.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _teardown(ctx, fn) -> None:
    from botocore.exceptions import ClientError

    deadline = _deadline(ctx)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _GONE_CODES:
                return
            if code not in _IN_USE_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_lb_and_wait(ctx, elbv2, lb_arn: str) -> None:
    """DeleteLoadBalancer, then poll until DescribeLoadBalancers no longer resolves the ARN."""
    from botocore.exceptions import ClientError

    _teardown(ctx, lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    deadline = _deadline(ctx)
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still resolves at the teardown deadline")
        time.sleep(2)


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
    ctx.on_cleanup(lambda: _teardown(ctx, lambda: ec2.delete_security_group(GroupId=sg_id)))
    return sg_id


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-tg-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _teardown(ctx, lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(ctx, elbv2, lb_arn))
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


def _import_acm_cert(ctx, cn: str, lb_arn: str) -> str:
    """Import a self-signed certificate; its teardown first deletes the load balancer using it."""
    key_pem, cert_pem = _self_signed_cert(cn)
    acm = ctx.client("acm")
    elbv2 = ctx.client("elbv2")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    arn = resp["CertificateArn"]

    def _cleanup() -> None:
        _delete_lb_and_wait(ctx, elbv2, lb_arn)
        _teardown(ctx, lambda: acm.delete_certificate(CertificateArn=arn))

    ctx.on_cleanup(_cleanup)
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
    return resp["Listeners"][0]["ListenerArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
