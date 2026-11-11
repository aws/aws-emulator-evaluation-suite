"""deploy-trust-store-cfn-associates-with-listener."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-trust-store-cfn-associates-with-listener"
GROUP = "deploy"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed trust store and mTLS HTTPS listener are linked: DescribeTrustStoreAssociations
    lists the load balancer and DescribeListeners points MutualAuthentication at the trust store."""
    subnets = _get_default_subnets(ctx)
    ca_cert_pem, _ca_key_pem = _openssl_self_signed_cert(ctx, "sim2real-elbv2-trust-ca")
    server_cert_pem, server_key_pem = _openssl_self_signed_cert(ctx, "sim2real-elbv2-server")
    bundle = _upload_ca_bundle(ctx, ca_cert_pem)
    cert_arn = _import_acm_cert(ctx, server_cert_pem, server_key_pem)
    alb_arn = _create_alb(ctx, subnets["subnet_ids"])

    ts_name = _short_name(ctx, "sim2realts")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AlbArn": {"Type": "String"},
            "CertArn": {"Type": "String"},
            "BundleBucket": {"Type": "String"},
            "BundleKey": {"Type": "String"},
        },
        "Resources": {
            "TrustStore": {
                "Type": "AWS::ElasticLoadBalancingV2::TrustStore",
                "Properties": {
                    "Name": ts_name,
                    "CaCertificatesBundleS3Bucket": {"Ref": "BundleBucket"},
                    "CaCertificatesBundleS3Key": {"Ref": "BundleKey"},
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "DependsOn": "TrustStore",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "AlbArn"},
                    "Port": 443,
                    "Protocol": "HTTPS",
                    "Certificates": [{"CertificateArn": {"Ref": "CertArn"}}],
                    "SslPolicy": "ELBSecurityPolicy-2016-08",
                    "MutualAuthentication": {"Mode": "verify", "TrustStoreArn": {"Ref": "TrustStore"}},
                    "DefaultActions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "200",
                                "ContentType": "text/plain",
                                "MessageBody": "ok",
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "TrustStoreArn": {"Value": {"Ref": "TrustStore"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
        },
    }
    outputs = _deploy_cfn(
        ctx,
        template,
        parameters=[
            {"ParameterKey": "AlbArn", "ParameterValue": alb_arn},
            {"ParameterKey": "CertArn", "ParameterValue": cert_arn},
            {"ParameterKey": "BundleBucket", "ParameterValue": bundle["bucket"]},
            {"ParameterKey": "BundleKey", "ParameterValue": bundle["key"]},
        ],
    )
    ts_arn = outputs["TrustStoreArn"]
    listener_arn = outputs["ListenerArn"]

    elbv2 = ctx.client("elbv2")
    status = _poll_trust_store_status(ctx, ts_arn, want_status="ACTIVE", timeout_s=90.0)
    assert status == "ACTIVE", f"trust store never reached ACTIVE, last={status!r}"

    associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assoc_arns = {a["ResourceArn"] for a in associations}
    # Real AWS records the association against the load balancer that owns the mTLS-enabled
    # listener (not the listener ARN itself) -- verify the deployed ALB shows up.
    assert alb_arn in assoc_arns, f"deployed load balancer {alb_arn!r} not in associations {assoc_arns!r}"

    listeners = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"]
    mutual_auth = listeners[0]["MutualAuthentication"]
    assert mutual_auth["Mode"] == "verify", f"expected MutualAuthentication Mode 'verify', got {mutual_auth!r}"
    assert mutual_auth["TrustStoreArn"] == ts_arn, (
        f"listener's MutualAuthentication.TrustStoreArn {mutual_auth.get('TrustStoreArn')!r} "
        f"does not point back at the deployed trust store {ts_arn!r}"
    )


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
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this branches on ctx.region, it does not pin the bucket to a fixed region.
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
    name = _short_name(ctx, "sim2realtsalb")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Scheme="internet-facing")
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_lb_active(ctx, lb_arn)
    return lb_arn


def _deploy_cfn(ctx, template_body: dict, parameters: list[dict] | None = None) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-tsstack-")
    kwargs = {"StackName": stack_name, "TemplateBody": json.dumps(template_body)}
    if parameters:
        kwargs["Parameters"] = parameters
    cfn.create_stack(**kwargs)

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_cleanup)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as exc:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [e.get("ResourceStatusReason", "") for e in events if "FAILED" in e.get("ResourceStatus", "")]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_trust_store_status(
    ctx, ts_arn: str, want_status: str = "ACTIVE", timeout_s: float = 90.0, interval_s: float = 5.0
) -> str | None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stores = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
        last = stores[0]["Status"]
        if last == want_status:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
