"""add-listener-certificates-too-many-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "add-listener-certificates-too-many-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding more certificates than the per-listener quota raises TooManyCertificatesException;
    freeing exactly one slot then lets the identical, previously rejected call succeed."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)
    default_cert_arn = _import_acm_cert(ctx, "sim2real-default.example.com", lb_arn)
    listener_arn = _create_https_listener(ctx, lb_arn, tg_arn, default_cert_arn)

    # The "certificates per Application Load Balancer" quota is account-adjustable, so its real
    # enforced value can differ from the documented default of 25 (and can't be trusted from a
    # service-quotas lookup either, since that call can be unavailable/permission-denied, or can
    # simply report a value that no longer matches what's actually enforced). Rather than
    # precompute an exact quota number, add non-default certificates one at a time -- a single
    # AddListenerCertificates call is itself capped at just 1 certificate ARN (real AWS returns a
    # request-shape ValidationError -- "Up to '1' certificate ARNs can be specified" -- if you try
    # to submit more than one per call) -- until the API itself rejects one with
    # TooManyCertificatesException, bounding the number of attempts as a safety net against an
    # unbounded loop.
    from botocore.exceptions import ClientError

    added_certs: list[str] = []
    code = message = None
    overflow_cert_arn = None
    max_attempts = 200
    for i in range(max_attempts):
        cert_arn = _import_acm_cert(ctx, f"sim2real-cert-{i}.example.com", lb_arn)
        try:
            elbv2.add_listener_certificates(
                ListenerArn=listener_arn, Certificates=[{"CertificateArn": cert_arn}]
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            overflow_cert_arn = cert_arn
            break
        added_certs.append(cert_arn)
    else:
        raise AssertionError(f"did not hit the certificate quota after {max_attempts} attempts")

    # Real AWS's ELBv2 API is an older "query" protocol service whose wire-level error Code
    # historically drops the "Exception" suffix present in the modeled/SDK exception class name
    # (e.g. the documented Error Code for this operation is "TooManyCertificates", while the
    # generated botocore exception class is named TooManyCertificatesException). The ClientError's
    # Error.Code reflects the wire value, so assert against the undecorated form.
    assert code == "TooManyCertificates", f"expected TooManyCertificates, got {code}"
    expected_message = "The maximum number of certificates has been reached"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected certificate should not have been attached; only the accepted ones (plus the
    # listener's default certificate) should be present.
    certs_after = elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    assert len(certs_after) == len(added_certs) + 1, (
        f"expected default + {len(added_certs)} accepted certs attached, got {len(certs_after)}"
    )
    assert all(c["CertificateArn"] != overflow_cert_arn for c in certs_after), (
        f"rejected certificate {overflow_cert_arn} is attached despite TooManyCertificates"
    )

    # Restore: freeing exactly one slot must let the identical, previously rejected call succeed --
    # proving the rejection tracked the listener's certificate count, not the certificate itself.
    freed_cert_arn = added_certs[0]
    elbv2.remove_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": freed_cert_arn}]
    )
    elbv2.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": overflow_cert_arn}]
    )

    certs_final = {
        c["CertificateArn"]
        for c in elbv2.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    }
    assert overflow_cert_arn in certs_final, "previously rejected certificate is not attached after retry"
    assert freed_cert_arn not in certs_final, "removed certificate is still attached"

    # Verified teardown inside the check's own time budget: ACM can hold this many certificates
    # in use for many minutes after the load balancer is gone, longer than the registered
    # cleanups get. Detaching every certificate and deleting the listener first releases them
    # through ELB rather than through the load balancer's asynchronous deletion. The registered
    # cleanups stay as the failure-path net and find everything gone here.
    import time

    acm = ctx.client("acm")
    for arn in certs_final - {default_cert_arn}:
        elbv2.remove_listener_certificates(ListenerArn=listener_arn, Certificates=[{"CertificateArn": arn}])
    elbv2.delete_listener(ListenerArn=listener_arn)
    _delete_lb_and_wait(elbv2, lb_arn)
    deadline = time.monotonic() + 1200.0
    for arn in [default_cert_arn, *added_certs, overflow_cert_arn]:
        _teardown(
            lambda arn=arn: acm.delete_certificate(CertificateArn=arn),
            timeout_s=max(deadline - time.monotonic(), 0.0),
        )


# A load balancer deletes asynchronously: DeleteLoadBalancer returns while the listener still holds
# its certificates and target group and its ENIs still sit in the security group. Each teardown
# delete therefore retries the in-use rejection inside a bounded window and re-raises a final
# failure; a not-found means the resource is already gone.
_IN_USE_CODES = ("ResourceInUse", "ResourceInUseException", "DependencyViolation")
_GONE_CODES = (
    "LoadBalancerNotFound", "TargetGroupNotFound", "ResourceNotFoundException", "InvalidGroup.NotFound"
)


def _teardown(fn, timeout_s: float = 600.0) -> None:
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
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
        time.sleep(10)


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 300.0) -> None:
    """DeleteLoadBalancer, then poll until DescribeLoadBalancers no longer resolves the ARN."""
    import time

    from botocore.exceptions import ClientError

    _teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still resolves {timeout_s}s after delete")
        time.sleep(5)


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
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_security_group_when_free(ec2, sg_id)))
    return sg_id


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-tg-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip")
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_target_group_when_free(elbv2, tg_arn)))
    return tg_arn


def _create_alb(ctx, subnet_ids, sg_id: str, scheme: str = "internal") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme=scheme, Type="application"
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
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
        _delete_lb_and_wait(elbv2, lb_arn)
        _teardown(lambda: acm.delete_certificate(CertificateArn=arn))

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
