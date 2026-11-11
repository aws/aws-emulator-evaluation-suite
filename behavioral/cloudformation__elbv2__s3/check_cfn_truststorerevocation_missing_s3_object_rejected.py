"""cfn-truststorerevocation-missing-s3-object-rejected."""
from __future__ import annotations

import datetime
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-truststorerevocation-missing-s3-object-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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


_REJECTED = (
    "Provided revocation content was not found (Service: ElasticLoadBalancingV2, Status Code: "
    "400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)


def _make_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-elbv2-tsrneg-ca")])
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
    bucket = ctx.unique_name("sim2real-elbv2-tsrneg-").lower().replace("_", "-")
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


def _template(ts_name: str, bucket: str, *, revocation_key: str | None) -> str:
    resources = {
        "TrustStore": {
            "Type": "AWS::ElasticLoadBalancingV2::TrustStore",
            "Properties": {
                "Name": ts_name,
                "CaCertificatesBundleS3Bucket": bucket,
                "CaCertificatesBundleS3Key": "ca-bundle.pem",
            },
        },
    }
    if revocation_key is not None:
        resources["Revocation"] = {
            "Type": "AWS::ElasticLoadBalancingV2::TrustStoreRevocation",
            "Properties": {
                "TrustStoreArn": {"Ref": "TrustStore"},
                "RevocationContents": [
                    {"S3Bucket": bucket, "S3Key": revocation_key, "RevocationType": "CRL"}
                ],
            },
        }
    return json.dumps(
        {
            "Resources": resources,
            "Outputs": {"TrustStoreArn": {"Value": {"Ref": "TrustStore"}},
                        **({"RevocationRef": {"Value": {"Ref": "Revocation"}}}
                           if revocation_key is not None else {})},
        }
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrustStoreRevocation naming an S3 object never uploaded is refused.

    ELBv2's exact not-found reason rolls the stack back and removes its trust store, while the
    same template naming the uploaded CRL deploys a revocation with one revoked entry.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")

    ca_key, ca_cert, x509, hashes, serialization = _make_ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_pem)

    ts_name = ctx.unique_name("sim2real-ts-")[:32].rstrip("-")
    broken_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-tsrnegbroken-"),
                             _template(ts_name, bucket, revocation_key="does-not-exist.pem"))
    status = wait_stack(cfn, broken_id)
    assert status == "ROLLBACK_COMPLETE", f"a missing revocation object ended {status!r}"
    events = stack_events(cfn, broken_id)
    got = handler_reason(failed_reason(events, "Revocation"), ctx.account, ts_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    created = [e["PhysicalResourceId"] for e in events
               if e["LogicalResourceId"] == "TrustStore" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(created) == 1, f"the trust store must have been created before the refusal: {created!r}"
    ts_arn = created[0]
    # The rollback removed the trust store it had created, before this check's own delete.
    trust_store_gone = _trust_store_not_found(ts_arn)
    expect_error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]), *trust_store_gone)
    delete_stack(cfn, broken_id)

    # Positive control: the same template with the revocation naming the uploaded CRL.
    crl_pem = _make_crl(ca_key, ca_cert, x509, hashes, serialization, revoked_serial=999002)
    s3.put_object(Bucket=bucket, Key="revocation.pem", Body=crl_pem)
    control_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-tsrnegok-"),
                              _template(ts_name, bucket, revocation_key="revocation.pem"))
    status = wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", f"the control stack ended {status!r}"
    out = stack_outputs(cfn, control_id)
    stores = paginate(elbv2, "describe_trust_stores", "TrustStores", Names=[ts_name])
    got = [(t["TrustStoreArn"], t["Name"], t["TotalRevokedEntries"]) for t in stores]
    assert got == [(out["TrustStoreArn"], ts_name, 1)], f"control trust store reads {got!r}"
    revocations = paginate(elbv2, "describe_trust_store_revocations", "TrustStoreRevocations",
                           TrustStoreArn=out["TrustStoreArn"])
    got = [(f"{r['RevocationId']}|{out['TrustStoreArn']}", r["RevocationType"],
            r["NumberOfRevokedEntries"]) for r in revocations]
    assert got == [(out["RevocationRef"], "CRL", 1)], f"control revocations {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
