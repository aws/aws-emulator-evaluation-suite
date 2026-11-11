"""deploy-trust-store-deletion-rejected-while-in-use."""
from __future__ import annotations

import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-trust-store-deletion-rejected-while-in-use"
GROUP = "deploy"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trust store still associated with a live HTTPS listener must reject DeleteTrustStore
    with TrustStoreInUse, leaving the trust store and its association intact; once the
    listener (and thus the association) is removed, the same DeleteTrustStore call must succeed."""
    subnets = _get_default_subnets(ctx)
    cert_pem, key_pem = _openssl_self_signed_cert(ctx, "sim2real-elbv2-negtest")
    cert_arn = _import_acm_cert(ctx, cert_pem, key_pem)
    bundle = _upload_ca_bundle(ctx, cert_pem)
    alb_arn = _create_alb(ctx, subnets["subnet_ids"])

    elbv2 = ctx.client("elbv2")
    ts_name = _short_name(ctx, "sim2realtsneg")
    ts_arn = elbv2.create_trust_store(
        Name=ts_name, CaCertificatesBundleS3Bucket=bundle["bucket"], CaCertificatesBundleS3Key=bundle["key"]
    )["TrustStores"][0]["TrustStoreArn"]
    ts_deleted = False

    def _cleanup_ts():
        if not ts_deleted:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)

    ctx.on_cleanup(_cleanup_ts)
    _poll_trust_store_status(ctx, ts_arn, want_status="ACTIVE", timeout_s=90.0)

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Port=443,
        Protocol="HTTPS",
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn},
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
    )["Listeners"][0]["ListenerArn"]
    listener_deleted = False

    def _cleanup_listener():
        if not listener_deleted:
            elbv2.delete_listener(ListenerArn=listener_arn)

    ctx.on_cleanup(_cleanup_listener)

    associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    # Real AWS records the association against the load balancer that owns the mTLS-enabled
    # listener (not the listener ARN itself).
    got_associations = {a["ResourceArn"] for a in associations}
    assert got_associations == {alb_arn}, f"expected association with {alb_arn!r}, got {got_associations!r}"

    # Break exactly one thing: try to delete a trust store that is still in use.
    code, message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    assert code == "TrustStoreInUse", f"expected TrustStoreInUse, got {code!r}"
    assert message == f"Trust store with ARN '{ts_arn}' is currently associated", f"delete_trust_store MESSAGE={message!r}"

    # Effect absent: the trust store still exists and is still associated with the listener.
    stores = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert len(stores) == 1, f"expected the rejected delete to leave exactly 1 trust store, found {len(stores)}"
    associations_after = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    got_after = {a["ResourceArn"] for a in associations_after}
    assert got_after == {alb_arn}, f"expected association with {alb_arn!r} to survive the rejected delete, got {got_after!r}"

    # Positive control in the same file: remove the association, then the identical delete call
    # must succeed.
    elbv2.delete_listener(ListenerArn=listener_arn)
    listener_deleted = True
    _poll_no_associations(ctx, ts_arn, timeout_s=60.0)
    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    ts_deleted = True

    code_after, message_after = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code_after == "TrustStoreNotFound", f"expected TrustStoreNotFound, got {code_after!r}"
    assert message_after == f"Trust store ARN '{ts_arn}' not found", f"describe_trust_stores MESSAGE={message_after!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _short_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _get_default_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az: dict[str, dict] = {}
    for s in resp.get("Subnets", []):
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError(
            "account has no default VPC with subnets in >=2 distinct AZs; "
            "an ALB requires at least 2 AZ subnets and this check has no fallback VPC provisioning"
        )
    chosen = list(by_az.values())[:2]
    return {"subnet_ids": [s["SubnetId"] for s in chosen], "vpc_id": chosen[0]["VpcId"]}


def _openssl_self_signed_cert(ctx, common_name: str) -> tuple[str, str]:
    import subprocess
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="sim2real-cert-")
    key_path = f"{tmpdir}/key.pem"
    cert_path = f"{tmpdir}/cert.pem"
    require_tools("openssl")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "2", "-nodes",
                "-subj", f"/CN={common_name}",
                "-addext", f"subjectAltName=DNS:{common_name}",
                "-addext", "keyUsage=digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
                "-keyout", key_path, "-out", cert_path,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        raise AssertionError(f"openssl failed to generate self-signed cert: {exc.stderr!r}")
    with open(cert_path) as f:
        cert_pem = f.read()
    with open(key_path) as f:
        key_pem = f.read()
    return cert_pem, key_pem


def _upload_ca_bundle(ctx, ca_cert_pem: str) -> dict:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-trustbundle-").lower()[:63].rstrip("-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=ca_cert_pem.encode())

    def _cleanup():
        s3.delete_object(Bucket=bucket, Key=key)
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return {"bucket": bucket, "key": key}


def _import_acm_cert(ctx, cert_pem: str, key_pem: str) -> str:
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem.encode(), PrivateKey=key_pem.encode())
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn


def _poll_lb_active(ctx, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        state = lbs[0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never became active, last state {state!r}")


def _create_alb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = _short_name(ctx, "sim2realtsnalb")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Scheme="internet-facing")
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_lb_active(ctx, lb_arn)
    return lb_arn


def _poll_trust_store_status(
    ctx, ts_arn: str, want_status: str = "ACTIVE", timeout_s: float = 90.0, interval_s: float = 5.0
) -> str:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stores = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
        last = stores[0]["Status"]
        if last == want_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"trust store never reached status={want_status!r}, last={last!r}")


def _poll_no_associations(ctx, ts_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
        last = associations
        if not associations:
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store associations never cleared after listener deletion, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
