"""cfn-elbv2-truststorerevocation-resource-lifecycle."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-truststorerevocation-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2", "s3"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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


_REVOKED_SERIAL = 999001


def _make_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-tsr-ca")])
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
    return key, cert, x509, hashes, serialization


def _make_crl(ca_key, ca_cert, x509, hashes, serialization, revoked_serial: int) -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc)
    revoked = x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-tsr-").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint naming itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})

    def _cleanup_bucket() -> None:
        try:
            objs = paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                return
            raise
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _trust_store_not_found(ts_arn: str) -> tuple[str, str]:
    return ("TrustStoreNotFound", f"Trust store ARN '{ts_arn}' not found")


def _template(ts_name: str, bucket: str, with_revocation: bool = True) -> str:
    template = (
        {
            "Resources": {
                "TrustStore": {
                    "Type": "AWS::ElasticLoadBalancingV2::TrustStore",
                    "Properties": {
                        "Name": ts_name,
                        "CaCertificatesBundleS3Bucket": bucket,
                        "CaCertificatesBundleS3Key": "ca-bundle.pem",
                    },
                },
                "Revocation": {
                    "Type": "AWS::ElasticLoadBalancingV2::TrustStoreRevocation",
                    "Properties": {
                        "TrustStoreArn": {"Ref": "TrustStore"},
                        "RevocationContents": [
                            {"S3Bucket": bucket, "S3Key": "revocation.pem", "RevocationType": "CRL"}
                        ],
                    },
                },
            },
            "Outputs": {
                "TrustStoreArn": {"Value": {"Ref": "TrustStore"}},
                "RevocationRef": {"Value": {"Ref": "Revocation"}},
            },
        }
    )
    if not with_revocation:
        del template["Resources"]["Revocation"], template["Outputs"]["RevocationRef"]
    return json.dumps(template)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrustStore and TrustStoreRevocation read back through ELBv2.

    The Refs match what ELBv2 lists (one CA, one revoked entry); an update dropping the
    revocation removes it from the live store, and the stack delete removes the store.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    ca_key, ca_cert, x509, hashes, serialization = _make_ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    crl_pem = _make_crl(ca_key, ca_cert, x509, hashes, serialization, _REVOKED_SERIAL)

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_pem)
    s3.put_object(Bucket=bucket, Key="revocation.pem", Body=crl_pem)

    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-tsrstack-"),
                            _template(ts_name, bucket))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    ts_arn = outputs["TrustStoreArn"]

    # Each Ref against an independent ELBv2 read: the store by name, the revocations by store.
    stores = paginate(elbv2, "describe_trust_stores", "TrustStores", Names=[ts_name])
    got = [(t["TrustStoreArn"], t["Name"], t["Status"], t["NumberOfCaCertificates"],
            t["TotalRevokedEntries"]) for t in stores]
    assert got == [(ts_arn, ts_name, "ACTIVE", 1, 1)], f"trust store {ts_name!r} reads {got!r}"
    revocations = paginate(elbv2, "describe_trust_store_revocations", "TrustStoreRevocations",
                           TrustStoreArn=ts_arn)
    got = [(r["RevocationType"], r["NumberOfRevokedEntries"]) for r in revocations]
    assert got == [("CRL", 1)], f"revocations of {ts_arn!r}: {revocations!r}"
    revocation_id = revocations[0]["RevocationId"]
    assert outputs["RevocationRef"] == f"{revocation_id}|{ts_arn}", (
        f"Ref Revocation {outputs['RevocationRef']!r}, expected '{revocation_id}|{ts_arn}'"
    )

    # The revocation's own delete: an update dropping it while the store still answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(ts_name, bucket, with_revocation=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"revocation-removing update ended {status!r}"
    left = paginate(elbv2, "describe_trust_store_revocations", "TrustStoreRevocations",
                    TrustStoreArn=ts_arn)
    assert left == [], f"after dropping the Revocation the store lists {left!r}"
    store = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert store["TotalRevokedEntries"] == 0, f"store after the update {store!r}"

    delete_stack(cfn, stack_id)
    trust_store_gone = _trust_store_not_found(ts_arn)
    expect_error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]), *trust_store_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
