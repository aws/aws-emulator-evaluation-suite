"""delete-shared-trust-store-association-same-account-fails."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-shared-trust-store-association-same-account-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSharedTrustStoreAssociation on a same-account association fails with DeleteAssociationSameAccount and
    the exact message and keeps the association, which turning mutual authentication off then removes."""
    elbv2 = ctx.client("elbv2")

    vpc_id, subnet_ids = _default_vpc_two_subnets(ctx)
    sg_id = _new_security_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)
    # Created before the load balancer so LIFO cleanup deletes the load balancer (and its
    # listener) before the certificate and trust store it holds.
    cert_arn = _import_acm_cert(ctx, "sim2real-mtls.example.com")
    ts_arn = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-"))
    lb_arn = _create_alb(ctx, subnet_ids, sg_id)

    listener_arn = _create_https_listener(
        ctx, lb_arn, tg_arn, cert_arn, mutual_authentication={"Mode": "verify", "TrustStoreArn": ts_arn}
    )

    _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60,
        interval_s=3,
        description="load balancer appearing in trust store associations",
    )

    code, message = _error(
        lambda: elbv2.delete_shared_trust_store_association(TrustStoreArn=ts_arn, ResourceArn=listener_arn)
    )
    # Real AWS raises this error as "DeleteAssociationSameAccount" (no "Exception" suffix on the wire code).
    assert code == "DeleteAssociationSameAccount", (
        f"expected DeleteAssociationSameAccount, got {code}"
    )
    expected = (
        f"Cannot remove the association because the trust store ARN '{ts_arn}' and "
        f"resource ARN '{listener_arn}' belong to the same account"
    )
    assert message == expected, f"MSG={message!r}"

    associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    # Real AWS reports the trust store association at the load balancer level, not per-listener.
    assert any(a["ResourceArn"] == lb_arn for a in associations), (
        "association should remain untouched after the rejected call"
    )

    # Positive control: disassociation itself works, only the
    # cross-account-only DeleteSharedTrustStoreAssociation call rejecting a same-account
    # target is. Detach the supported way (turn mutual auth off on the listener) and
    # require the association to actually clear -- otherwise a target that unconditionally
    # rejects DeleteSharedTrustStoreAssociation with DeleteAssociationSameAccount, without
    # ever supporting a real cross-account disassociation, would score identically to a
    # correct one.
    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})

    associations_after = _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: not any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60,
        interval_s=3,
        description="load balancer clearing from trust store associations after detaching mutual auth",
    )
    assert not any(a["ResourceArn"] == lb_arn for a in associations_after), (
        f"association still present after detaching mutual auth: {associations_after}"
    )


# ===== helpers =====
def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message). An unexpected
    SUCCESS raises rather than reading as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


_GONE = {"ResourceNotFoundException", "TrustStoreNotFound", "LoadBalancerNotFound",
         "TargetGroupNotFound", "InvalidGroup.NotFound"}
_BUSY = {"ResourceInUseException", "TrustStoreInUse"}


def _safe_call(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries while the deleting listener still holds it."""
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
    return resp["Listeners"][0]["ListenerArn"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=bucket)
    objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
    objects += [
        {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
    ]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_trust_store(ctx, cn: str) -> str:
    _key_pem, cert_pem = _self_signed_cert(cn)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
    )
    ts_arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description="trust store reaching ACTIVE",
    )
    return ts_arn


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
