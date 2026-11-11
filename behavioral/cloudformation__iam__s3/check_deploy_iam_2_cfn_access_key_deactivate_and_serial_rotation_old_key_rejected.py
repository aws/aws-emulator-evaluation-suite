"""deploy-iam-2-cfn-access-key-deactivate-and-serial-rotation-old-key-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-2-cfn-access-key-deactivate-and-serial-rotation-old-key-rejected"
GROUP = "deploy-iam-cfn-user-group-accesskey"
SERVICES = ["cloudformation", "iam", "s3"]

_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = [{"Key": "sim2real", "Value": "deploy-iam-cfn-user-group-accesskey"}]


def _call(fn):
    """('OK', None) when the call succeeds, else (exact AWS error code, error message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    return "OK", None


def _client_as(ctx, key_id, secret, service="s3"):
    """A client signing as the CFN-deployed access key, never with the caller's credentials."""
    return ctx.client(
        service, creds={"aws_access_key_id": key_id, "aws_secret_access_key": secret}
    )


def _settle(probe, accept, *, description, streak=3, timeout_s=150, interval_s=3):
    """Poll probe() until accept(result) holds on `streak` CONSECUTIVE calls; return the last result.

    IAM is eventually consistent and no API reports a key as live (or dead) for S3, so the signed
    request is its own observable. A streak keeps one lagging replica from being read as steady
    state. Bounded: running out of time is a FAIL quoting what was seen.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    seen, run, last = [], 0, None
    while True:
        last = probe()
        seen.append(last)
        run = run + 1 if accept(last) else 0
        if run >= streak:
            print(f"[settle] {description}: {time.monotonic() - start:.1f}s, {len(seen)} probes")
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not settled {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-8:]!r}"
            )
        time.sleep(interval_s)


def _stack_status(cfn, name):
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response.get("Error", {}).get("Message", ""):
            return "GONE"
        raise


def _wait_stack(cfn, name, terminal, *, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _stack_status(cfn, name)
        if status in terminal:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {name} still {status!r} after {timeout_s}s")


def _delete_stack_and_wait(cfn, name):
    """Teardown: delete the stack and confirm it is gone; a failure raises."""
    try:
        cfn.delete_stack(StackName=name)
        status = _wait_stack(cfn, name, {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"}, timeout_s=300)
        if status == "DELETE_FAILED":
            raise RuntimeError(f"cloudformation stack {name} ended DELETE_FAILED")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"cloudformation stack {name} teardown failed: {exc!r}") from exc


def _drop_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _template(bucket, user_name, *, status, serial):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "User": {
                "Type": "AWS::IAM::User",
                "Properties": {
                    "UserName": user_name,
                    "Tags": _TAGS,
                    "Policies": [{
                        "PolicyName": "read-scratch-bucket",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                           "Resource": f"arn:aws:s3:::{bucket}/*"}],
                        },
                    }],
                },
            },
            "Key": {
                "Type": "AWS::IAM::AccessKey",
                "Properties": {"UserName": {"Ref": "User"}, "Status": status, "Serial": serial},
            },
        },
        "Outputs": {
            "AccessKeyId": {"Value": {"Ref": "Key"}},
            "SecretAccessKey": {"Value": {"Fn::GetAtt": ["Key", "SecretAccessKey"]}},
        },
    })


def _update(cfn, stack, body):
    cfn.update_stack(StackName=stack, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"],
                     Tags=_TAGS)
    status = _wait_stack(cfn, stack, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                                      "UPDATE_ROLLBACK_FAILED"}, timeout_s=300)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}, expected UPDATE_COMPLETE"
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}


def _keys(iam, user):
    return sorted((k["AccessKeyId"], k["Status"])
                  for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"])


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AWS::IAM::AccessKey `Status: Inactive` updates in place (same key id) and S3 then rejects the
    key; a bumped `Serial` replaces it with a new key S3 accepts, while the old key is rejected as
    unknown. A signed GetObject of the object's exact bytes is the positive control.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name(f"{_XSVC_PREFIX}cfnrot-").lower()[:63]
    user_name = ctx.unique_name(f"{_XSVC_PREFIX}cfnrot-u-")[:64]
    stack = ctx.unique_name(f"{_XSVC_PREFIX}cfnrot-stk-")[:128]
    obj = "rotation/probe.bin"
    body = uuid.uuid4().bytes * 8

    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    s3.put_object(Bucket=bucket, Key=obj, Body=body)

    # v1: Active key, Serial 1 -- the positive control.
    ctx.verify_account_safety()
    cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(bucket, user_name, status="Active", serial=1),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_stack(cfn, stack, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE",
                                      "ROLLBACK_FAILED"}, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}, expected CREATE_COMPLETE"
    out1 = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    key1 = out1["AccessKeyId"]
    as_key1 = _client_as(ctx, key1, out1["SecretAccessKey"])
    assert _keys(iam, user_name) == [(key1, "Active")], f"IAM keys after create: {_keys(iam, user_name)!r}"

    ok = _settle(lambda: _call(lambda: as_key1.get_object(Bucket=bucket, Key=obj)),
                 lambda r: r[0] == "OK", description="GetObject with the v1 deployed key")
    assert ok == ("OK", None), f"v1 key GetObject: {ok!r}"
    read = as_key1.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert read == body, f"v1 key read {len(read)} bytes, not the {len(body)} written"

    # v2: Status Inactive -- in place, same id, and S3 stops honouring the key.
    out2 = _update(cfn, stack, _template(bucket, user_name, status="Inactive", serial=1))
    assert out2["AccessKeyId"] == key1, (
        f"Status is an in-place update; the key id changed {key1!r} -> {out2['AccessKeyId']!r}"
    )
    assert _keys(iam, user_name) == [(key1, "Inactive")], f"IAM keys after deactivate: {_keys(iam, user_name)!r}"
    inactive = _settle(lambda: _call(lambda: as_key1.get_object(Bucket=bucket, Key=obj)),
                       lambda r: r[0] == "InvalidAccessKeyId", timeout_s=180, interval_s=5,
                       description="GetObject with the deactivated key")
    assert inactive[0] == "InvalidAccessKeyId", f"a deactivated key must be refused; got {inactive!r}"
    assert inactive[1] == "The AWS Access Key Id you provided does not exist in our records.", f"InvalidAccessKeyId message: {inactive!r}"

    # v3: Active again, Serial 2 -- replacement: a new key works, the old one is gone.
    out3 = _update(cfn, stack, _template(bucket, user_name, status="Active", serial=2))
    key2 = out3["AccessKeyId"]
    assert key2 != key1, f"a Serial bump must replace the key; id stayed {key1!r}"
    assert _keys(iam, user_name) == [(key2, "Active")], (
        f"after replacement IAM must hold only the new key {key2!r}; got {_keys(iam, user_name)!r}"
    )
    as_key2 = _client_as(ctx, key2, out3["SecretAccessKey"])
    ok2 = _settle(lambda: _call(lambda: as_key2.get_object(Bucket=bucket, Key=obj)),
                  lambda r: r[0] == "OK", description="GetObject with the replacement key")
    assert ok2 == ("OK", None), f"replacement key GetObject: {ok2!r}"
    read2 = as_key2.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert read2 == body, f"replacement key read {len(read2)} bytes, not the {len(body)} written"
    old = _call(lambda: as_key1.get_object(Bucket=bucket, Key=obj))
    assert old[0] == "InvalidAccessKeyId", f"the replaced key must stay unknown to S3; got {old!r}"
    assert old[1] == "The AWS Access Key Id you provided does not exist in our records.", f"InvalidAccessKeyId message: {old!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
