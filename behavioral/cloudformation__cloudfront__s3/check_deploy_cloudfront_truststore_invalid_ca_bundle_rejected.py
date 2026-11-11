"""deploy-cloudfront-truststore-invalid-ca-bundle-rejected."""
from __future__ import annotations

import datetime
import json
import re
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "deploy-cloudfront-truststore-invalid-ca-bundle-rejected"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


# ---- Check-specific: the template, then run(). ----

_GOOD_KEY, _BAD_KEY = "good-ca.pem", "bad-ca.pem"
_REJECTED = (
    "Invalid request provided: AWS::CloudFront::TrustStore: The request contains an invalid CA "
    "Certificates Bundle. (Service: CloudFront, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


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


def _template(bucket_name, trust_store=None):
    """The bucket, plus a TrustStore ``(name, key)`` built from that bucket's object."""
    resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
        "BucketName": bucket_name, "PublicAccessBlockConfiguration": _BLOCK_ALL,
    }}}
    if trust_store is not None:
        name, key = trust_store
        resources["TrustStore"] = {"Type": "AWS::CloudFront::TrustStore", "Properties": {
            "Name": name,
            "CaCertificatesBundleSource": {"CaCertificatesBundleS3Location": {
                "Bucket": {"Ref": "Bucket"}, "Key": key, "Region": {"Ref": "AWS::Region"},
            }},
        }}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrustStore whose S3 object is not a CA certificates bundle fails and rolls
    back with no trust store left, while the same template at a valid bundle deploys.
    """
    s3 = ctx.client("s3")
    cfront = ctx.client("cloudfront")
    cf = ctx.client("cloudformation")
    bucket_name = ctx.unique_name("sim2real-cfnts-neg-bucket-")
    good_name = ctx.unique_name("sim2real-cfnts-good-")
    bad_name = ctx.unique_name("sim2real-cfnts-bad-")

    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnts-neg-"), _template(bucket_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"bucket stack ended {status!r}"
    pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    assert pab == _BLOCK_ALL, f"bucket public access block {pab!r}"

    # Both bundles are check setup, uploaded directly; their deletes run (LIFO) before the bucket's.
    s3.put_object(Bucket=bucket_name, Key=_GOOD_KEY, Body=_self_signed_ca_pem())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=_GOOD_KEY))
    s3.put_object(Bucket=bucket_name, Key=_BAD_KEY, Body=b"this is not a PEM certificate")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=_BAD_KEY))

    # The update adding a TrustStore on the non-bundle object fails and rolls back.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(bucket_name, (bad_name, _BAD_KEY)))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rejected update ended {status!r}"
    rows = validation_rows(cf, stack_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cf, stack_id), "TrustStore")
    got = handler_reason(reason, ctx.account, bad_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    listed = [t for t in paginate(cfront, "list_trust_stores", "TrustStoreList")
              if t["Name"] in (good_name, bad_name)]
    assert listed == [], f"the rolled-back trust store is listed: {listed!r}"

    # Positive control: the same template with only the Key pointing at a valid bundle.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(bucket_name, (good_name, _GOOD_KEY)))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"control update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    listed = [t for t in paginate(cfront, "list_trust_stores", "TrustStoreList")
              if t["Name"] in (good_name, bad_name)]
    got = [(t["Name"], t["Status"], t["NumberOfCaCertificates"]) for t in listed]
    assert got == [(good_name, "active", 1)], f"ListTrustStores after the control {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
