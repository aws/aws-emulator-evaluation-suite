"""access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["rolesanywhere"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity allowed rolesanywhere:CreateProfile creates a profile; with an explicit Deny for
    the action the call is refused with HTTP 403 and creates nothing; with the Deny removed it
    succeeds again and the profile is listed by ListProfiles.
    """
    iam = ctx.client("iam")
    base = ctx.client("rolesanywhere")
    sts = ctx.client("sts")

    user_name = ctx.unique_name("sim2real-ra-denyuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": "access-denied-without-permission-rejected"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"]))

    scoped_client = ctx.client(
        "rolesanywhere",
        creds={
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )

    account_id = sts.get_caller_identity()["Account"]
    # Two distinct fabricated role ARNs: RolesAnywhere rejects a second profile referencing a
    # roleArn already attached to a live profile with ValidationException, which would otherwise
    # mask the IAM-layer denial this check asserts.
    baseline_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"
    denied_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ra-role-')}"
    profile_name = ctx.unique_name("sim2real-ra-profile-")

    # CreateProfile with roleArns set also requires iam:PassRole on the referenced role, and
    # CreateProfile with tags set also requires rolesanywhere:TagResource; AWS answers
    # AccessDeniedException naming each action the Allow omits.
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["rolesanywhere:CreateProfile", "rolesanywhere:ListProfiles", "rolesanywhere:TagResource"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": [baseline_role_arn, denied_role_arn]},
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName="allow-create-profile", PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName="allow-create-profile"))
    profile_tags = [{"key": "sim2real", "value": "access-denied-without-permission-rejected"}]

    # Positive control: the Allow-only identity can create the profile on its own signed call.
    baseline = _poll_for_success(scoped_client, profile_name, baseline_role_arn, profile_tags, timeout_s=60.0)
    ctx.on_cleanup(lambda: base.delete_profile(profileId=baseline["profileId"]))
    assert baseline["name"] == profile_name, f"expected {profile_name!r}, baseline create returned {baseline!r}"

    # Break exactly one thing: an explicit Deny for the same action, on the same identity.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "rolesanywhere:CreateProfile", "Resource": "*"}],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName="deny-create-profile", PolicyDocument=json.dumps(deny_policy)
    )
    ctx.on_cleanup(lambda: _delete_user_policy_ignore_missing(iam, user_name, "deny-create-profile"))

    denied_profile_name = ctx.unique_name("sim2real-ra-denied-profile-")
    code, status = _poll_for_stable_denial(
        scoped_client, denied_profile_name, denied_role_arn, ra_cleanup=base, timeout_s=60.0
    )
    # An explicit-deny IAM policy is enforced at the IAM authorization layer
    # before the request reaches the RolesAnywhere service. Rely on the HTTP
    # status code (403) as the stable signal -- the exact error Code string
    # returned for an IAM-layer deny varies by call path.
    assert status == 403, f"unexpected status {status!r} / code {code!r}"
    assert not _profile_name_in_list(base, denied_profile_name), (
        f"{denied_profile_name!r} must not exist after a denied CreateProfile"
    )

    # Restore: remove the Deny, then the identical call succeeds.
    iam.delete_user_policy(UserName=user_name, PolicyName="deny-create-profile")
    restored = _poll_for_success(scoped_client, denied_profile_name, denied_role_arn, profile_tags, timeout_s=60.0)
    ctx.on_cleanup(lambda: base.delete_profile(profileId=restored["profileId"]))

    # Terminal read: independent of both the mutating CreateProfile call and its own response.
    assert _profile_name_in_list(base, denied_profile_name), (
        f"{denied_profile_name!r} must be visible via ListProfiles after the Deny is removed and "
        "the identical call is retried"
    )


def _poll_for_stable_denial(denied_client, profile_name, role_arn, ra_cleanup, timeout_s: float, interval_s: float = 2.0):
    """Repeatedly attempt CreateProfile with the (soon-to-be) denied
    credentials. Newly minted IAM access keys and newly attached inline deny
    policies can each take a few seconds to fully propagate, and those two
    propagation delays are independent -- so a call attempted in the narrow
    window where the key is already usable but the deny policy has not yet
    taken effect can spuriously succeed. If that happens, clean up the
    unexpectedly-created profile and keep polling until the denial becomes
    stable (or the timeout is reached)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            created = denied_client.create_profile(name=profile_name, roleArns=[role_arn])["profile"]
            # Unexpected success -- the deny policy hasn't propagated yet.
            ra_cleanup.delete_profile(profileId=created["profileId"])
            time.sleep(interval_s)
            continue
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code == "InvalidClientTokenId":
                # fresh IAM access key not yet propagated/recognized -- retry
                time.sleep(interval_s)
                continue
            return code, status
    raise AssertionError("the deny policy never took effect within the timeout")


def _poll_for_success(client, profile_name, role_arn, tags_kv, timeout_s: float, interval_s: float = 2.0):
    """Retry CreateProfile until it succeeds. Covers two independent propagation delays: a
    freshly minted IAM access key (InvalidClientTokenId) and a just-granted or just-removed
    identity policy (AccessDeniedException) can each lag a few seconds behind the IAM call that
    set them. Raises on timeout rather than returning a failure value -- a caller must never read
    "still denied" as "created"."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return client.create_profile(name=profile_name, roleArns=[role_arn], tags=tags_kv)["profile"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_profile never succeeded within {timeout_s}s: {last_exc}")


def _delete_user_policy_ignore_missing(iam, user_name: str, policy_name: str) -> None:
    """Teardown for a policy the body may already have removed."""
    from botocore.exceptions import ClientError

    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _profile_name_in_list(ra, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ra.list_profiles(**kwargs)
        if any(p["name"] == name for p in resp.get("profiles", [])):
            return True
        next_token = resp.get("nextToken")
        if not next_token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
