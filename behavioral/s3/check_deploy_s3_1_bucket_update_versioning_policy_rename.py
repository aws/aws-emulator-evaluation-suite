"""deploy-s3-1-bucket-update-versioning-policy-rename."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-1-bucket-update-versioning-policy-rename"
GROUP = "deploy-s3-bucket-update"
SERVICES = ["s3"]

# One template, driven through three in-place UpdateStacks by parameter alone, so each update
# changes exactly one property: VersioningConfiguration, then the BucketPolicy's Effect, then
# BucketName (the only one of the three that requires replacement).
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketNameParam:
    Type: String
  VersioningStatus:
    Type: String
    AllowedValues: [Enabled, Suspended]
  ReaderEffect:
    Type: String
    AllowedValues: [Allow, Deny]
Resources:
  ReaderRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:root'
            Action: sts:AssumeRole
      Tags:
        - Key: sim2real
          Value: deploy-s3-1-bucket-update-versioning-policy-rename
  Bucket:
    Type: AWS::S3::Bucket
    UpdateReplacePolicy: Retain
    Properties:
      BucketName: !Ref BucketNameParam
      VersioningConfiguration:
        Status: !Ref VersioningStatus
      Tags:
        - Key: sim2real
          Value: deploy-s3-1-bucket-update-versioning-policy-rename
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: ReaderGetObject
            Effect: !Ref ReaderEffect
            Principal:
              AWS: !GetAtt ReaderRole.Arn
            Action: s3:GetObject
            Resource: !Sub 'arn:${AWS::Partition}:s3:::${Bucket}/*'
Outputs:
  BucketName:
    Value: !Ref Bucket
  ReaderRoleArn:
    Value: !GetAtt ReaderRole.Arn
"""

_KEY = "doc.txt"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Three UpdateStacks on a stack-owned bucket each show at the data plane: versioning suspended
    in place, a policy Deny that blocks a reader role but not the owner, and a rename whose
    UpdateReplacePolicy Retain leaves the old bucket and its versions readable."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-s3d1-")
    old_bucket = ctx.unique_name("sim2real-s3d1-a-")
    new_bucket = ctx.unique_name("sim2real-s3d1-b-")

    # Registered FIRST so it runs LAST: after the rename the retained old bucket is outside the
    # stack, and only this deletes it.
    ctx.on_cleanup(lambda: _delete_bucket_fully(s3, old_bucket))

    params = {"BucketNameParam": old_bucket, "VersioningStatus": "Enabled", "ReaderEffect": "Allow"}
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=_params(params),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name))
    _wait_stack(ctx, cfn, stack_name, "CREATE_COMPLETE")

    outputs = _outputs(cfn, stack_name)
    assert outputs.get("BucketName") == old_bucket, (
        f"stack output BucketName {outputs.get('BucketName')!r}, expected {old_bucket!r}"
    )
    role_arn = outputs["ReaderRoleArn"]
    assert _physical_id(cfn, stack_name, "Bucket") == old_bucket, (
        f"Bucket physical id {_physical_id(cfn, stack_name, 'Bucket')!r}, expected {old_bucket!r}"
    )

    # ---- baseline: versioning Enabled, two versions, the reader role can read ----
    v1 = s3.put_object(Bucket=old_bucket, Key=_KEY, Body=b"version-one")
    v2 = s3.put_object(Bucket=old_bucket, Key=_KEY, Body=b"version-two")
    vid1, vid2 = v1.get("VersionId"), v2.get("VersionId")
    assert vid1 and vid2 and vid1 != vid2 and "null" not in (vid1, vid2), (
        f"versioning-Enabled bucket minted VersionIds {vid1!r}, {vid2!r}; expected two distinct real ids"
    )

    reader_creds, reader_arn = _assume(ctx, role_arn)
    reader = ctx.client("s3", creds=reader_creds)
    body = _reader_get_until_allowed(ctx, reader, old_bucket, _KEY)
    assert body == b"version-two", f"reader role read {body!r} under the Allow policy, expected b'version-two'"

    # ---- update 1: VersioningConfiguration Enabled -> Suspended, in place ----
    params["VersioningStatus"] = "Suspended"
    _update(ctx, cfn, stack_name, params)
    phys = _physical_id(cfn, stack_name, "Bucket")
    assert phys == old_bucket, f"versioning update changed the physical bucket to {phys!r}; expected in-place {old_bucket!r}"
    status = s3.get_bucket_versioning(Bucket=old_bucket).get("Status")
    assert status == "Suspended", f"get_bucket_versioning Status {status!r} after the update, expected 'Suspended'"

    v3 = s3.put_object(Bucket=old_bucket, Key=_KEY, Body=b"version-three")
    assert "VersionId" not in v3, (
        f"PutObject on a Suspended bucket returned VersionId {v3.get('VersionId')!r}; expected none"
    )
    for vid, want in ((vid1, b"version-one"), (vid2, b"version-two")):
        got = s3.get_object(Bucket=old_bucket, Key=_KEY, VersionId=vid)["Body"].read()
        assert got == want, f"pre-suspension version {vid!r} now reads {got!r}, expected {want!r}"
    current = s3.get_object(Bucket=old_bucket, Key=_KEY)
    assert current["Body"].read() == b"version-three", "current object is not the post-suspension write"
    assert current.get("VersionId") == "null", (
        f"current object after a Suspended-bucket write has VersionId {current.get('VersionId')!r}, expected 'null'"
    )
    versions = [v for v in s3.list_object_versions(Bucket=old_bucket, Prefix=_KEY).get("Versions", [])
                if v["Key"] == _KEY]
    ids = sorted(v["VersionId"] for v in versions)
    assert ids == sorted([vid1, vid2, "null"]), f"versions after suspension {ids!r}, expected {sorted([vid1, vid2, 'null'])!r}"

    # ---- update 2: rewrite the BucketPolicy to Deny the reader role s3:GetObject ----
    params["ReaderEffect"] = "Deny"
    _update(ctx, cfn, stack_name, params)
    stmt = json.loads(s3.get_bucket_policy(Bucket=old_bucket)["Policy"])["Statement"]
    effects = sorted(s.get("Effect") for s in stmt)
    assert effects == ["Deny"], f"bucket policy effects after the Deny update: {effects!r}"

    code, message = _reader_get_until_denied(ctx, reader, old_bucket, _KEY)
    assert code == "AccessDenied", f"reader role GetObject under the Deny policy returned {code!r}, expected 'AccessDenied'"
    want = (f"User: {reader_arn} is not authorized to perform: s3:GetObject on resource: "
            f"\"arn:aws:s3:::{old_bucket}/{_KEY}\" with an explicit deny in a resource-based policy")
    assert message == want, f"reader role GetObject under the Deny policy said {message!r}, expected {want!r}"
    # Positive control in the same state: the owner is not named by the Deny and still reads.
    owner_body = s3.get_object(Bucket=old_bucket, Key=_KEY)["Body"].read()
    assert owner_body == b"version-three", f"owner read {owner_body!r} under the Deny policy, expected b'version-three'"

    # ---- update 3: BucketName change => replacement; UpdateReplacePolicy Retain keeps the old ----
    params["BucketNameParam"] = new_bucket
    ctx.on_cleanup(lambda: _delete_bucket_fully(s3, new_bucket))
    _update(ctx, cfn, stack_name, params)
    phys = _physical_id(cfn, stack_name, "Bucket")
    assert phys == new_bucket, f"Bucket physical id after the rename is {phys!r}, expected {new_bucket!r}"
    assert phys != old_bucket, "rename did not replace the bucket"
    s3.head_bucket(Bucket=new_bucket)
    new_keys = s3.list_objects_v2(Bucket=new_bucket).get("KeyCount")
    assert new_keys == 0, f"replacement bucket {new_bucket!r} should start empty, has KeyCount {new_keys!r}"

    s3.head_bucket(Bucket=old_bucket)  # raises if the Retain policy did not keep it
    kept = s3.get_object(Bucket=old_bucket, Key=_KEY)["Body"].read()
    assert kept == b"version-three", f"retained old bucket's object reads {kept!r}, expected b'version-three'"
    kept_v1 = s3.get_object(Bucket=old_bucket, Key=_KEY, VersionId=vid1)["Body"].read()
    assert kept_v1 == b"version-one", f"retained old bucket lost version {vid1!r}: read {kept_v1!r}"


def _params(d: dict) -> list:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in d.items()]


def _outputs(cfn: Any, stack_name: str) -> dict:
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _physical_id(cfn: Any, stack_name: str, logical_id: str) -> str:
    r = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return r["StackResourceDetail"]["PhysicalResourceId"]


def _failure_events(cfn: Any, stack_name: str) -> list:
    out = []
    for ev in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:25]:
        if "FAILED" in ev.get("ResourceStatus", ""):
            out.append((ev["LogicalResourceId"], ev["ResourceStatus"], ev.get("ResourceStatusReason")))
    return out


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx: Any, cfn: Any, stack_name: str, want: str, cap_s: float = 900) -> None:
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.time() + timeout_s
    status = None
    while time.time() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if not status.endswith("_IN_PROGRESS"):
            raise AssertionError(
                f"stack {stack_name} reached {status!r}, expected {want!r}; "
                f"failures: {_failure_events(cfn, stack_name)!r}"
            )
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} to reach {want!r}: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s, expected {want!r}")


def _update(ctx: Any, cfn: Any, stack_name: str, params: dict) -> None:
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=_params(params),
        Capabilities=["CAPABILITY_IAM"],
    )
    _wait_stack(ctx, cfn, stack_name, "UPDATE_COMPLETE")


def _assume(ctx: Any, role_arn: str) -> tuple[dict, str]:
    """AssumeRole on the stack's reader role, retrying while the new role's trust propagates.
    Returns the session credentials and the assumed-role ARN."""
    sts = ctx.client("sts")
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=ctx.unique_name("s3d1-"))
            c = resp["Credentials"]
            return {
                "aws_access_key_id": c["AccessKeyId"],
                "aws_secret_access_key": c["SecretAccessKey"],
                "aws_session_token": c["SessionToken"],
            }, resp["AssumedRoleUser"]["Arn"]
        except ClientError as exc:
            last = exc
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"assuming the stack's reader role {role_arn!r}: the run budget ended first; not graded")
    raise AssertionError(f"could not assume the stack's reader role {role_arn!r}: {last!r}")


def _err(fn: Any) -> str:
    """The ClientError code fn raised; raises AssertionError if fn unexpectedly succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "<no code>")
    raise AssertionError("call succeeded; an error was expected")


def _reader_get_until_allowed(ctx: Any, reader: Any, bucket: str, key: str) -> bytes:
    """First use of fresh session credentials against an Allow policy: bounded retry while the
    new role and its session propagate (IAM exposes no condition to poll)."""
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while time.monotonic() < deadline:
        try:
            return reader.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last not in ("AccessDenied", "InvalidAccessKeyId", "InvalidToken"):
                raise
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"reader role to read {bucket}/{key} under the Allow policy: the run budget ended first; not graded")
    raise AssertionError(f"reader role never read {bucket}/{key} under the Allow policy; last error {last!r}")


def _reader_get_until_denied(ctx: Any, reader: Any, bucket: str, key: str) -> tuple[str, str]:
    """Poll the reader's GetObject until the rewritten policy takes effect; return the error
    (code, message).
    A reader that keeps succeeding for the whole window is the over-permissive failure."""
    timeout_s = _budget_s(ctx, 90)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            reader.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code", "<no code>"), err.get("Message")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"reader role to be denied {bucket}/{key}: the run budget ended first; not graded")
    raise AssertionError(f"reader role still reads {bucket}/{key} {timeout_s:.0f}s after the policy was rewritten to Deny")


def _empty_bucket(s3: Any, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000], "Quiet": True}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_bucket_fully(s3: Any, bucket: str) -> None:
    try:
        _empty_bucket(s3, bucket)
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("NoSuchBucket", "404"):
            return
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"s3 bucket {bucket}: {exc!r}") from exc
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"s3 bucket {bucket}: {exc!r}") from exc


def _teardown_stack(ctx: Any, stack_name: str) -> None:
    """Empty every version out of the stack's current bucket, then delete the stack and wait."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    try:
        try:
            bucket = _physical_id(cfn, stack_name, "Bucket")
        except ClientError as err:
            # The stack, or its Bucket resource, already gone: ValidationError "... does not exist"
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "does not exist" not in error.get("Message", ""):
                raise
            bucket = None
        if bucket:
            try:
                _empty_bucket(s3, bucket)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
                    raise
        cfn.delete_stack(StackName=stack_name)
        deadline = time.time() + 600
        while time.time() < deadline:
            try:
                st = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                # CloudFormation answers a deleted stack with ValidationError "... does not exist"
                error = err.response["Error"]
                if error["Code"] != "ValidationError" or "does not exist" not in error.get("Message", ""):
                    raise
                return
            if st == "DELETE_COMPLETE":
                return
            if st == "DELETE_FAILED":
                raise RuntimeError(f"cloudformation stack {stack_name} DELETE_FAILED: "
                                   f"{_failure_events(cfn, stack_name)!r}")
            time.sleep(2)
        raise RuntimeError(f"cloudformation stack {stack_name} not deleted within 600s")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"cloudformation stack {stack_name}: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
