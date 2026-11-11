"""policy-simulation-explicit-deny-overrides-allow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-simulation-explicit-deny-overrides-allow"
GROUP = 'policy_simulation'
SERVICES = ['iam']

_ALLOW = "sim2real-behav-deny-allow"
_DENY = "sim2real-behav-deny-explicit"
_ORIGINAL_BODY = b"original-bytes"
_RESTORED_BODY = b"restored-bytes"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _outcome(fn):
    """(code, message) of the captured AWS error, or ("UNEXPECTED_SUCCESS", None) -- a sentinel
    that cannot be mistaken for an error code -- on success."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return "UNEXPECTED_SUCCESS", None


def _error_code(fn):
    """The captured AWS error code, or the "UNEXPECTED_SUCCESS" sentinel on success."""
    return _outcome(fn)[0]


def _client_for_credentials(ctx, access_key_id, secret_access_key, service):
    """A client signing AS the minted principal, built by ``ctx.client`` so it keeps this
    target's endpoint, region and TLS settings."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _decisions(iam, source_arn, actions, resource_arn):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=[resource_arn]
    )["EvaluationResults"]
    return {r["EvalActionName"]: r["EvalDecision"] for r in results}


def _cleanup(iam, s3, user_name, bucket):
    try:
        for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            try:
                iam.delete_user_policy(UserName=user_name, PolicyName=name)
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            try:
                iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:happy-path", "cap:c7", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An explicit Deny on s3:PutObject for one object overrides a broader s3:* Allow on real
    signed calls and in SimulatePrincipalPolicy, leaves GetObject allowed, and is reversible.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    user_name = ctx.unique_name("sim2real-behav-iam-sim-deny-user-")
    bucket = ctx.unique_name("sim2real-behav-iam-sim-deny-").lower().replace("_", "-")

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _cleanup(iam, s3, user_name, bucket))
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    # CreateBucket rejects LocationConstraint for us-east-1 specifically -- an S3 API quirk, not a
    # region pin for this check, which runs wherever ctx.region says.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    scratch_key = "scratch.txt"
    target_key = "object.txt"
    s3.put_object(Bucket=bucket, Key=scratch_key, Body=b"scratch")
    s3.put_object(Bucket=bucket, Key=target_key, Body=_ORIGINAL_BODY)
    target_arn = f"arn:aws:s3:::{bucket}/{target_key}"

    # Broad Allow across the whole bucket, no Deny yet.
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"], "s3")

    # --- Positive control: under the Allow alone, this principal can write in the bucket at all.
    # A scratch key is used, never the target key -- S3's authorization decision for an exact
    # (access key, action, resource) triple appears to be cached past when the policy changes
    # underneath it, so exercising PutObject on the target key here would contaminate the later
    # Deny check with a stale 'allowed' answer for that exact triple.
    _poll(
        lambda: _error_code(
            lambda: as_user.put_object(Bucket=bucket, Key=scratch_key, Body=b"scratch")
        ),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for a real signed PutObject",
    )

    # --- Break exactly one thing: an explicit Deny naming s3:PutObject on the target object, and
    # nothing else. PutObject, not DeleteObject: S3 answers a denied DeleteObject with a 204, so a
    # delete cannot show enforcement.
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=_DENY,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Deny", "Action": "s3:PutObject", "Resource": target_arn}
                ],
            }
        ),
    )

    # A PutObject right after the Deny is created can still succeed while S3's authorization cache
    # for this (access key, action, resource) triple catches up. Each such attempt is a real write,
    # so the poll only finds when the Deny holds; the bytes it wrote along the way are not asserted.
    denied, denied_message = _poll(
        lambda: _outcome(
            lambda: as_user.put_object(Bucket=bucket, Key=target_key, Body=b"attempted-overwrite")
        ),
        lambda o: o[0] != "UNEXPECTED_SUCCESS",
        timeout_s=250,
        interval_s=5,
        description="the explicit Deny takes effect on the real signed PutObject",
    )
    assert denied == "AccessDenied", (
        "an explicit Deny naming s3:PutObject on this object must refuse the real signed call "
        f"with exactly AccessDenied; got {denied!r}"
    )
    expected_denial = (
        f"User: {user_arn} is not authorized to perform: s3:PutObject on resource: "
        f'"{target_arn}" with an explicit deny in an identity-based policy'
    )
    assert denied_message == expected_denial, (
        f"expected message {expected_denial!r}, got {denied_message!r}"
    )

    # Confirm it, with a call whose body we KNOW cannot be on the object if this is refused: a
    # second, independent observation on the fresh marker, not a repeat of the one just above.
    marker = b"post-deny-marker"
    confirm, confirm_message = _outcome(
        lambda: as_user.put_object(Bucket=bucket, Key=target_key, Body=marker)
    )
    assert confirm == "AccessDenied", (
        f"the Deny must still refuse a second, independent real signed PutObject; got {confirm!r}"
    )
    assert confirm_message == expected_denial, (
        f"expected message {expected_denial!r}, got {confirm_message!r}"
    )

    # Effect absent AND scoped in one independent read: GetObject is untouched by the Deny (it
    # names only s3:PutObject), so it must still succeed -- and the bytes it returns must NOT be
    # the marker the just-denied write tried to leave behind.
    body_now = as_user.get_object(Bucket=bucket, Key=target_key)["Body"].read()
    assert body_now != marker, (
        "the Deny is scoped to s3:PutObject, so GetObject on the same object must still succeed, "
        f"and the denied write must not have taken effect; got body {body_now!r}"
    )

    # The simulator must agree with what the two real calls just did, while the Deny is still live.
    # It is IAM's prediction, not the S3 authorizer, so it is asserted alongside the real calls.
    sim = _poll(
        lambda: _decisions(iam, user_arn, ["s3:PutObject", "s3:GetObject"], target_arn),
        lambda d: d.get("s3:PutObject") == "explicitDeny",
        timeout_s=30,
        interval_s=3,
        description="the simulator reports explicitDeny for s3:PutObject",
    )
    assert sim["s3:PutObject"] == "explicitDeny", (
        f"expected explicitDeny to override the broad allow, got {sim['s3:PutObject']!r}"
    )
    assert sim["s3:GetObject"] == "allowed", (
        f"expected the untouched action to remain allowed, got {sim['s3:GetObject']!r}"
    )

    # --- Restore the one change: the identical PutObject call must now succeed and actually stick.
    iam.delete_user_policy(UserName=user_name, PolicyName=_DENY)
    restored = _poll(
        lambda: _error_code(
            lambda: as_user.put_object(Bucket=bucket, Key=target_key, Body=_RESTORED_BODY)
        ),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=40,
        interval_s=3,
        description="deleting the Deny restores the real signed PutObject",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        "removing the Deny must restore the Allow's grant on the identical PutObject call; got "
        f"{restored!r}"
    )
    final_body = as_user.get_object(Bucket=bucket, Key=target_key)["Body"].read()
    assert final_body == _RESTORED_BODY, (
        f"the restored PutObject must have actually written through; got body {final_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
