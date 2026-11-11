"""deploy-trust-store-cfn-association-enforced."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "deploy-trust-store-cfn-association-enforced"
GROUP = "deploy"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed TrustStore + HTTPS listener association is queryable, and a
    revocation added afterward through the API is reflected in the trust store's
    revoked-entry count and listing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key, ca_cert = _make_ca(x509, hashes, rsa, NameOID)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    leaf_key, leaf_cert = _make_leaf(x509, hashes, rsa, NameOID)
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    acm = ctx.client("acm")
    cert_resp = acm.import_certificate(Certificate=leaf_cert_pem, PrivateKey=leaf_key_pem)
    cert_arn = cert_resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))

    bucket, ca_key_name = _upload_bundle(ctx, "ca-bundle.pem", ca_pem)

    vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)

    stack_name = ctx.unique_name("sim2real-tscfn-")
    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    lb_name = ctx.unique_name("sim2real-lb-")[:32].rstrip("-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TS": {
                "Type": "AWS::ElasticLoadBalancingV2::TrustStore",
                "Properties": {
                    "Name": ts_name,
                    "CaCertificatesBundleS3Bucket": bucket,
                    "CaCertificatesBundleS3Key": ca_key_name,
                },
            },
            "LB": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Name": lb_name,
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": subnet_ids,
                    "SecurityGroups": [sg_id],
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "LB"},
                    "Port": 443,
                    "Protocol": "HTTPS",
                    "SslPolicy": "ELBSecurityPolicy-2016-08",
                    "Certificates": [{"CertificateArn": cert_arn}],
                    "MutualAuthentication": {"Mode": "verify", "TrustStoreArn": {"Ref": "TS"}},
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
            "TrustStoreArn": {"Value": {"Ref": "TS"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
            "LoadBalancerArn": {"Value": {"Ref": "LB"}},
        },
    }
    outputs = _deploy_stack(ctx, stack_name, json.dumps(template))
    ts_arn = outputs["TrustStoreArn"]
    lb_arn = outputs["LoadBalancerArn"]

    elbv2 = ctx.client("elbv2")
    assocs = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    # Real AWS records the trust store association against the load balancer that owns the
    # mTLS-enabled listener, not the listener ARN itself.
    assert [a["ResourceArn"] for a in assocs] == [lb_arn], (
        f"expected the deployed load balancer {lb_arn!r} to be the sole association, got {assocs}"
    )

    crl_pem = _make_crl(x509, hashes, ca_key, ca_cert, revoked_serial=999001)
    crl_bucket, crl_key_name = _upload_bundle(ctx, "revocation.pem", crl_pem)
    add_resp = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": crl_bucket, "S3Key": crl_key_name, "RevocationType": "CRL"}],
    )
    revocation_id = add_resp["TrustStoreRevocations"][0]["RevocationId"]
    added_count = add_resp["TrustStoreRevocations"][0]["NumberOfRevokedEntries"]
    assert added_count == 1, f"expected 1 revoked entry from the CRL, got {added_count}"

    total = _wait_total_revoked(ctx, ts_arn, expected=1)
    assert total == 1, f"expected the trust store's TotalRevokedEntries to reach 1, last observed {total}"
    revocations = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    matching = [r for r in revocations if r["RevocationId"] == revocation_id]
    assert len(matching) == 1, (
        f"expected revocation id {revocation_id!r} to appear exactly once in "
        f"describe_trust_store_revocations, got {revocations}"
    )
    matched_count = matching[0]["NumberOfRevokedEntries"]
    assert matched_count == 1, (
        f"expected the listed revocation's NumberOfRevokedEntries to be 1, got {matched_count}"
    )


# ===== helpers =====


def _make_ca(x509, hashes, rsa, NameOID):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-test-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(x509, hashes, rsa, NameOID):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-test.example.com")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_crl(x509, hashes, ca_key, ca_cert, revoked_serial: int) -> bytes:
    from cryptography.hazmat.primitives import serialization

    now = datetime.datetime.utcnow()
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_serial)
        .revocation_date(now)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def _upload_bundle(ctx, key_name: str, content: bytes) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key=key_name, Body=content)
    return bucket, key_name


def _default_vpc_subnets_and_sg(ctx) -> tuple[str, list, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an ALB")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    subnet_ids = list(by_az.values())[:2]

    sg_name = ctx.unique_name("sim2real-tls-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check: allow inbound HTTPS",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
        ],
    )
    sg_id = sg["GroupId"]

    def _cleanup_sg() -> None:
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    ctx.on_cleanup(_cleanup_sg)
    return vpc_id, subnet_ids, sg_id


def _deploy_stack(ctx, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        # An ALB stack deletes within a few minutes; the wait is bounded at 600 s.
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_total_revoked(ctx, ts_arn: str, expected: int, timeout_s: float = 60.0, interval_s: float = 3.0) -> int:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        ts = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
        last = ts["TotalRevokedEntries"]
        if last >= expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"trust store {ts_arn} TotalRevokedEntries never reached {expected} within {timeout_s}s, "
        f"last observed {last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
