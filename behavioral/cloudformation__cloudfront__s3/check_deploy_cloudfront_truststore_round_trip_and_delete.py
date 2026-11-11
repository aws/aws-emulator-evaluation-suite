"""deploy-cloudfront-truststore-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "deploy-cloudfront-truststore-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND_CODE = "EntityNotFound"
_NOT_FOUND_MSG = "The specified trust store does not exist."
_KEY = "ca.pem"


def _self_signed_ca_pem() -> bytes:
    """A fresh per-run self-signed CA certificate PEM (no key material reused across runs)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-cfnts-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


_BLOCK_ALL = {
    "BlockPublicAcls": True, "BlockPublicPolicy": True,
    "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
}


def _bucket_template(bucket_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
                "BucketName": bucket_name, "PublicAccessBlockConfiguration": _BLOCK_ALL,
            }},
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    })


def _trust_store_template(name, bucket, key, region):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TrustStore": {"Type": "AWS::CloudFront::TrustStore", "Properties": {
                "Name": name,
                "CaCertificatesBundleSource": {"CaCertificatesBundleS3Location": {
                    "Bucket": bucket, "Key": key, "Region": region,
                }},
                "Tags": [{"Key": "sim2real-ts", "Value": name}],
            }},
        },
        "Outputs": {
            "TrustStoreRef": {"Value": {"Ref": "TrustStore"}},
            "TrustStoreArn": {"Value": {"Fn::GetAtt": ["TrustStore", "Arn"]}},
        },
    })


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrustStore built from an S3 CA bundle reads back through CloudFront.

    Ref and the Arn GetAtt match ListTrustStores, it holds 1 CA certificate and both tags, and
    deleting its stack removes the trust store while the bucket stack still stands.
    """
    s3 = ctx.client("s3")
    cfront = ctx.client("cloudfront")
    cf = ctx.client("cloudformation")
    bucket_name = ctx.unique_name("sim2real-cfnts-bucket-")
    bucket_stack = ctx.unique_name("sim2real-cfnts-bucketstack-")
    ts_stack = ctx.unique_name("sim2real-cfnts-tsstack-")
    ts_name = ctx.unique_name("sim2real-cfnts-")

    bucket_stack_id = create_stack(ctx, cf, bucket_stack, _bucket_template(bucket_name))
    status = wait_stack(cf, bucket_stack_id)
    assert status == "CREATE_COMPLETE", f"bucket stack ended {status!r}"
    assert stack_outputs(cf, bucket_stack_id) == {"BucketName": bucket_name}, "bucket Ref"
    pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    assert pab == _BLOCK_ALL, f"bucket public access block {pab!r}"
    tag_set = s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    bucket_tags = [t for t in tag_set if not t["Key"].startswith("aws:")]
    assert bucket_tags == [{"Key": "sim2real", "Value": bucket_stack}], f"bucket tags {tag_set!r}"

    # The CA bundle is check setup, uploaded directly; its delete runs (LIFO) before the bucket's.
    s3.put_object(Bucket=bucket_name, Key=_KEY, Body=_self_signed_ca_pem())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=_KEY))

    ts_stack_id = create_stack(ctx, cf, ts_stack,
                               _trust_store_template(ts_name, bucket_name, _KEY, ctx.region))
    status = wait_stack(cf, ts_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"trust store stack ended {status!r}: {_reasons(stack_events(cf, ts_stack_id))!r}"
    )
    out = stack_outputs(cf, ts_stack_id)

    # Ref against an independent read (ListTrustStores by the templated name).
    listed = [t for t in paginate(cfront, "list_trust_stores", "TrustStoreList")
              if t["Name"] == ts_name]
    assert [t["Id"] for t in listed] == [out["TrustStoreRef"]], (
        f"ListTrustStores found {listed!r} for Ref {out['TrustStoreRef']!r}"
    )
    ts = cfront.get_trust_store(Identifier=listed[0]["Id"])["TrustStore"]
    got = (ts["Name"], ts["Arn"], ts["Status"], ts["NumberOfCaCertificates"])
    assert got == (ts_name, listed[0]["Arn"], "active", 1), f"GetTrustStore reads {got!r}"
    assert out["TrustStoreArn"] == ts["Arn"], f"GetAtt Arn {out!r} != {ts['Arn']!r}"
    items = cfront.list_tags_for_resource(Resource=ts["Arn"])["Tags"].get("Items", [])
    got_tags = sorted((t["Key"], t["Value"]) for t in items)
    assert got_tags == [("sim2real", ts_stack), ("sim2real-ts", ts_name)], f"tags {got_tags!r}"

    # The trust store's own delete, while the bucket stack (its S3 source) still stands.
    delete_stack(cf, ts_stack_id)
    refused = (_NOT_FOUND_CODE, _NOT_FOUND_MSG)
    expect_error(lambda: cfront.get_trust_store(Identifier=listed[0]["Id"]), *refused)
    assert s3.head_object(Bucket=bucket_name, Key=_KEY)["ContentLength"] > 0, "bundle gone"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
