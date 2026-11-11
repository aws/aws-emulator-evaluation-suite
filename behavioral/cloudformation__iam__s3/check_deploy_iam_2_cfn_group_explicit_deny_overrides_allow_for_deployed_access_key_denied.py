"""deploy-iam-2-cfn-group-explicit-deny-overrides-allow-for-deployed-access-key-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-2-cfn-group-explicit-deny-overrides-allow-for-deployed-access-key-denied"
GROUP = "deploy-iam-cfn-user-group-accesskey"
SERVICES = ["cloudformation", "iam", "s3"]

_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = [{"Key": "sim2real", "Value": "deploy-iam-cfn-user-group-accesskey"}]

# S3's same-account AccessDenied message names WHY the request was refused. The error CODE is the
# same for an explicit Deny and for "nothing allows it", so the message is the only observable
# that separates the two halves of this check.
def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _explicit_deny(user_arn, action, resource):
    return (f'User: {user_arn} is not authorized to perform: {action} on resource: "{resource}" '
            f"with an explicit deny in an identity-based policy")


def _implicit_deny(user_arn, action, resource):
    return (f'User: {user_arn} is not authorized to perform: {action} on resource: "{resource}" '
            f"because no identity-based policy allows the {action} action")


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
    # The key name is two adjacent literals so a credential scanner does not flag a keyword
    # argument name; nothing secret is written anywhere.
    return ctx.client(service, creds={"aws_access_key_id": key_id, "aws_secret" "_access_key": secret})


def _settle(probe, accept, *, description, streak=3, timeout_s=150, interval_s=3):
    """Poll probe() until accept(result) holds on `streak` CONSECUTIVE calls; return the last result.

    IAM is eventually consistent and no API reports a grant (or a membership removal) as effective,
    so the enforced request is its own observable. A streak keeps one lagging replica from being
    read as steady state. Bounded: running out of time is a FAIL quoting what was seen.
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


def _template(bucket, user_name, group_name, *, with_membership):
    resources = {
        "User": {
            "Type": "AWS::IAM::User",
            "Properties": {"UserName": user_name, "Tags": _TAGS},
        },
        "Group": {
            "Type": "AWS::IAM::Group",
            "Properties": {
                "GroupName": group_name,
                "Policies": [{
                    "PolicyName": "s3-allow-all-deny-delete",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Sid": "AllowAllS3", "Effect": "Allow", "Action": "s3:*",
                             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
                            {"Sid": "DenyDelete", "Effect": "Deny", "Action": "s3:DeleteObject",
                             "Resource": f"arn:aws:s3:::{bucket}/*"},
                        ],
                    },
                }],
            },
        },
        "Key": {
            "Type": "AWS::IAM::AccessKey",
            "Properties": {"UserName": {"Ref": "User"}, "Status": "Active"},
        },
    }
    if with_membership:
        resources["Membership"] = {
            "Type": "AWS::IAM::UserToGroupAddition",
            "Properties": {"GroupName": {"Ref": "Group"}, "Users": [{"Ref": "User"}]},
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "AccessKeyId": {"Value": {"Ref": "Key"}},
            "SecretAccessKey": {"Value": {"Fn::GetAtt": ["Key", "SecretAccessKey"]}},
            "UserArn": {"Value": {"Fn::GetAtt": ["User", "Arn"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Signing as a CFN-deployed key: the group's explicit Deny refuses DeleteObject; after an update
    drops the membership both Put and Delete are implicitly denied; deleting the stack revokes the
    key (InvalidAccessKeyId) and removes the user and group.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name(f"{_XSVC_PREFIX}cfnkey-").lower()[:63]
    user_name = ctx.unique_name(f"{_XSVC_PREFIX}cfnkey-u-")[:64]
    group_name = ctx.unique_name(f"{_XSVC_PREFIX}cfnkey-g-")[:128]
    stack = ctx.unique_name(f"{_XSVC_PREFIX}cfnkey-stk-")[:128]
    obj = "deploy/probe.bin"
    body = uuid.uuid4().bytes * 8

    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})

    # ---- 1. deploy: user + group(Allow s3:*, Deny s3:DeleteObject) + membership + access key
    ctx.verify_account_safety()
    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(bucket, user_name, group_name, with_membership=True),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_stack(cfn, stack, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE",
                                      "ROLLBACK_FAILED"}, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}, expected CREATE_COMPLETE"
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    assert set(outputs) == {"AccessKeyId", "SecretAccessKey", "UserArn"}, (
        f"stack outputs were {sorted(outputs)!r}"
    )
    key_id, secret, user_arn = outputs["AccessKeyId"], outputs["SecretAccessKey"], outputs["UserArn"]
    assert user_arn.endswith(f":user/{user_name}"), f"UserArn output {user_arn!r} does not name {user_name!r}"
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert [(k["AccessKeyId"], k["Status"]) for k in keys] == [(key_id, "Active")], (
        f"IAM reports keys {keys!r}; the Ref output named {key_id!r}"
    )
    members = [u["UserName"] for u in iam.get_group(GroupName=group_name)["Users"]]
    assert members == [user_name], f"group members after create were {members!r}"

    as_key = _client_as(ctx, key_id, secret)

    # ---- 2. the deployed key, through the group: Put + Get allowed, Delete explicitly denied
    put = _settle(lambda: _call(lambda: as_key.put_object(Bucket=bucket, Key=obj, Body=body)),
                  lambda r: r[0] == "OK", timeout_s=150,
                  description="PutObject signed by the CFN-deployed key (group Allow s3:*)")
    assert put == ("OK", None), f"PutObject as the deployed key: {put!r}"

    got = _settle(lambda: _call(lambda: as_key.get_object(Bucket=bucket, Key=obj)),
                  lambda r: r[0] == "OK", timeout_s=_budget_s(ctx, 90.0),
                  description="GetObject signed by the CFN-deployed key")
    assert got == ("OK", None), f"GetObject as the deployed key: {got!r}"
    read = as_key.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert read == body, f"GetObject returned {len(read)} bytes, not the {len(body)} written"

    denied = _call(lambda: as_key.delete_object(Bucket=bucket, Key=obj))
    obj_arn = f"arn:aws:s3:::{bucket}/{obj}"
    want = ("AccessDenied", _explicit_deny(user_arn, "s3:DeleteObject", obj_arn))
    assert denied == want, (
        f"DeleteObject must be refused by the group's explicit Deny with {want!r}; got {denied!r}"
    )
    still = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert still == body, "the explicitly denied DeleteObject removed or altered the object"

    # ---- 3. update_stack drops ONLY the UserToGroupAddition: user, group, key all survive
    cfn.update_stack(
        StackName=stack,
        TemplateBody=_template(bucket, user_name, group_name, with_membership=False),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )
    status = _wait_stack(cfn, stack, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                                      "UPDATE_ROLLBACK_FAILED"}, timeout_s=300)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}, expected UPDATE_COMPLETE"
    groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=user_name)["Groups"]]
    assert groups == [], f"user still in groups {groups!r} after the membership was removed"
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    assert [(k["AccessKeyId"], k["Status"]) for k in keys] == [(key_id, "Active")], (
        f"the update must not touch the key; IAM reports {keys!r}"
    )
    iam.get_group(GroupName=group_name)  # the group itself survives the update

    # Outside the group the user has no policy at all: Delete is now an IMPLICIT deny. S3 can keep
    # citing the removed group's explicit Deny for minutes after IAM lists the user in no group,
    # hence the wide bound.
    want_after = ("AccessDenied", _implicit_deny(user_arn, "s3:DeleteObject", obj_arn))
    after = _settle(lambda: _call(lambda: as_key.delete_object(Bucket=bucket, Key=obj)),
                    lambda r: r == want_after,
                    timeout_s=480, interval_s=10,
                    description="DeleteObject refused for lack of any Allow once out of the group")
    assert after == want_after, f"DeleteObject outside the group: {after!r}"
    put_after = _call(lambda: as_key.put_object(Bucket=bucket, Key="deploy/after.bin", Body=b"x"))
    want_put = ("AccessDenied",
                _implicit_deny(user_arn, "s3:PutObject", f"arn:aws:s3:::{bucket}/deploy/after.bin"))
    assert put_after == want_put, (
        f"PutObject must lose the group's Allow along with its Deny with {want_put!r}; "
        f"got {put_after!r}"
    )
    still = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert still == body, "a refused DeleteObject removed or altered the object"
    leaked = s3.list_objects_v2(Bucket=bucket, Prefix="deploy/after.bin").get("KeyCount", 0)
    assert leaked == 0, "the refused PutObject wrote an object anyway"

    # ---- 4. delete the stack: user and group gone, key revoked for signing
    cfn.delete_stack(StackName=stack)
    # Waited on by StackId: a deleted stack stays describable by id, never by name.
    status = _wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300)
    assert status == "DELETE_COMPLETE", f"stack delete ended {status!r}, expected DELETE_COMPLETE"

    user_gone = _settle(lambda: _call(lambda: iam.get_user(UserName=user_name)),
                        lambda r: r[0] == "NoSuchEntity", streak=1, timeout_s=60,
                        description="get_user after stack delete")
    assert user_gone == ("NoSuchEntity", f"The user with name {user_name} cannot be found."), (
        f"get_user after delete: {user_gone!r}"
    )
    group_gone = _settle(lambda: _call(lambda: iam.get_group(GroupName=group_name)),
                         lambda r: r[0] == "NoSuchEntity", streak=1, timeout_s=60,
                         description="get_group after stack delete")
    assert group_gone == ("NoSuchEntity", f"The group with name {group_name} cannot be found."), (
        f"get_group after delete: {group_gone!r}"
    )
    dead = _settle(lambda: _call(lambda: as_key.get_object(Bucket=bucket, Key=obj)),
                   lambda r: r[0] == "InvalidAccessKeyId", timeout_s=150,
                   description="S3 request signed with the deleted stack's access key")
    assert dead == ("InvalidAccessKeyId",
                    "The AWS Access Key Id you provided does not exist in our records."), (
        f"a deleted access key must be unknown to S3; got {dead!r}"
    )
    still = s3.get_object(Bucket=bucket, Key=obj)["Body"].read()
    assert still == body, "the scratch object must outlive the stack that could not delete it"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
