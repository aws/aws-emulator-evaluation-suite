"""deploy-truststore-cfn-bundle-integrity-behaves."""
from __future__ import annotations

import json
import time
import urllib.request

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-truststore-cfn-bundle-integrity-behaves"
GROUP = "deploy"
SERVICES = ["elbv2"]

_TEMPLATE = json.dumps(
    {
        "Parameters": {
            "BucketName": {"Type": "String"},
            "BundleKey": {"Type": "String"},
            "TrustStoreName": {"Type": "String"},
        },
        "Resources": {
            "TrustStore": {
                "Type": "AWS::ElasticLoadBalancingV2::TrustStore",
                "Properties": {
                    "Name": {"Ref": "TrustStoreName"},
                    "CaCertificatesBundleS3Bucket": {"Ref": "BucketName"},
                    "CaCertificatesBundleS3Key": {"Ref": "BundleKey"},
                },
            },
        },
        "Outputs": {
            "TrustStoreArn": {"Value": {"Ref": "TrustStore"}},
        },
    }
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A trust store deployed via CloudFormation from a CA bundle object in S3 becomes ACTIVE and
    GetTrustStoreCaCertificatesBundle serves back byte-identical content to the source S3 object."""
    bundle_bytes = _generate_self_signed_ca_pem()
    bucket = _create_bucket(ctx)
    key = "ca-bundle.pem"
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=bundle_bytes)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    ts_name = ctx.unique_name("sim2real-ts-")
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        [
            {"ParameterKey": "BucketName", "ParameterValue": bucket},
            {"ParameterKey": "BundleKey", "ParameterValue": key},
            {"ParameterKey": "TrustStoreName", "ParameterValue": ts_name},
        ],
    )
    ts_arn = outputs["TrustStoreArn"]

    elbv2 = ctx.client("elbv2")
    ts = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda t: t["Status"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
    )
    assert ts["Status"] == "ACTIVE"
    assert ts["NumberOfCaCertificates"] == 1
    assert ts["Name"] == ts_name, (
        f"trust store Name is {ts['Name']!r}, expected the CFN TrustStoreName ref {ts_name!r}"
    )

    location = elbv2.get_trust_store_ca_certificates_bundle(TrustStoreArn=ts_arn)["Location"]
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
        fetched_bytes = resp.read()

    assert fetched_bytes == bundle_bytes


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _generate_self_signed_ca_pem():
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-trust-root")])
        now = datetime.datetime.now(datetime.timezone.utc)
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
        return cert.public_bytes(serialization.Encoding.PEM)
    except ImportError:
        pass

    import os
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        require_tools("openssl")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "1",
                "-nodes", "-subj", "/CN=sim2real-trust-root",
                "-keyout", key_path, "-out", cert_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            return f.read()


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-truststore-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _deploy_cfn(ctx, template_body, parameters):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
