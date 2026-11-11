"""get-federation-token-policy-caps-caller-permissions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-policy-caps-caller-permissions"
GROUP = 'overly-permissive'
SERVICES = ['sts']

#: What ``_error`` returns for a call that succeeds: a code no AWS error can carry.
_SUCCEEDED = ("<call succeeded>", None)

@tags("axis:rejection", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFederationToken's Policy caps the federated session: GetBucketLocation on an existing,
    caller-owned bucket is AccessDenied under a narrow policy and succeeds under a broad one,
    while a nonexistent bucket returns NoSuchBucket to both."""

    sts = ctx.client("sts")

    # Minted credentials go only to ctx.client(creds=...), never os.environ, where they
    # would shadow the container credential provider for every later check.

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _error(fn):
        """fn()'s error (code, message), or ``_SUCCEEDED`` (a code no error can carry)."""
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return _SUCCEEDED

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        """Bounded poll to a condition. Raises on deadline miss -- never a bare sleep."""
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})"
                )
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=120.0, what="call"):
        """Poll until fn() succeeds. Used for POSITIVE controls, where a transient
        InvalidClientTokenId or an unpropagated identity policy must not be read as a denial."""
        return _poll(
            lambda: _error(fn), lambda e: e == _SUCCEEDED,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _poll_denied(fn, expected, *, timeout_s=60.0, what="call"):
        """Poll until fn() fails with exactly `expected`. Called only after a positive control
        proved the credential live, so a deadline miss is the verdict."""
        return _poll(
            lambda: _error(fn), lambda e: e[0] == expected,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became refused with {expected}",
        )

    def _wait_creds_active(creds):
        # GetCallerIdentity requires no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error(lambda: probe.get_caller_identity()),
            lambda e: e == _SUCCEEDED, timeout_s=120.0, interval_s=2.0,
            description="temporary credentials became active",
        )

    identity_cache = {}

    def _identity():
        if not identity_cache:
            identity_cache.update(sts.get_caller_identity())
        return identity_cache

    def _account_id():
        return _identity()["Account"]

    def _caller_principal_arn():
        """The value real AWS puts in aws:PrincipalArn for this caller: for an assumed-role
        session that is the ROLE arn, not the assumed-role arn."""
        arn = _identity()["Arn"]
        if ":assumed-role/" in arn:
            role_name = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
            return f"arn:aws:iam::{_account_id()}:role/{role_name}"
        return arn

    def _tags_kv():
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ]

    def _trust_root(condition=None, actions=None):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_account_id()}:root"},
            "Action": actions if actions is not None else ["sts:AssumeRole"],
        }
        if condition is not None:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _allow(actions, resource="*", condition=None):
        stmt = {"Effect": "Allow", "Action": actions, "Resource": resource}
        if condition is not None:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _drop_role(iam, role_name):
        # Attached and inline policies both block delete_role, so remove them first.
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
        _poll(
            lambda: _error(lambda: iam.get_role(RoleName=role_name)),
            lambda e: e[0] == "NoSuchEntity", timeout_s=60.0, interval_s=2.0,
            description=f"role {role_name} disappeared",
        )

    def _create_role(iam, *, trust_policy, inline_policy=None, max_session_duration=3600):
        """Create a role, register its teardown at creation, and return (name, arn, id)."""
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        created = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )["Role"]
        ctx.on_cleanup(lambda: _drop_role(iam, role_name))
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="sim2real-behav-inline",
                PolicyDocument=json.dumps(inline_policy),
            )
        return role_name, created["Arn"], created["RoleId"]

    def _try_assume(client, role_arn, session_name, **kw):
        """Returns the AssumeRole response dict on success, or the error CODE string on
        failure -- so `result == "AccessDenied"` simultaneously proves the specific code AND
        that no credentials were issued."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, **kw
            )
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name, **kw):
        # Trust-policy propagation makes the first AssumeRole fail for seconds; negatives run
        # only after this positive control so propagation lag cannot pass as a refusal.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: isinstance(r, dict),
            timeout_s=180.0, interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _wait_assume_code(client, role_arn, session_name, expected, **kw):
        # The inverse, for a trust policy we just TIGHTENED: the refusal also takes seconds to
        # take effect, so poll until it appears instead of sleeping a fixed interval.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: r == expected,
            timeout_s=180.0, interval_s=3.0,
            description=f"AssumeRole on {role_arn} began returning {expected}",
        )

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")


    def _drop_bucket(s3_client, bucket):
        for page in s3_client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3_client.delete_object(Bucket=bucket, Key=obj["Key"])
        s3_client.delete_bucket(Bucket=bucket)
        _poll(
            lambda: _error(lambda: s3_client.head_bucket(Bucket=bucket)),
            lambda e: e[0] in {"404", "NoSuchBucket"}, timeout_s=60.0, interval_s=2.0,
            description=f"bucket {bucket} disappeared",
        )

    def _new_bucket(s3_client):
        """An empty bucket, so the authorization decision is reached: S3 resolves the bucket
        name before authorizing, and a nonexistent bucket is NoSuchBucket for any session."""
        bucket = ctx.unique_name("sim2real-behav-fedtgt-")
        params = {"Bucket": bucket}
        # us-east-1 is S3's implicit default: CreateBucket rejects an explicit
        # LocationConstraint of "us-east-1" itself, so the param is omitted only there.
        if ctx.region and ctx.region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3_client.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(s3_client, bucket))
        return bucket

    account = _account_id()
    owner_s3 = ctx.client("s3")
    target_bucket = _new_bucket(owner_s3)
    absent_bucket = ctx.unique_name("sim2real-behav-absent-")
    fed_name = ctx.unique_name("sim2real-behav-fed-")

    def _denied_message(action):
        return (
            f"User: arn:aws:sts::{account}:federated-user/{fed_name} is not authorized to "
            f'perform: {action} on resource: "arn:aws:s3:::{target_bucket}" because no session '
            f"policy allows the {action} action"
        )

    # GetFederationToken creates no resource; the federated session simply expires.
    narrow = sts.get_federation_token(
        Name=fed_name,
        Policy=json.dumps(_allow(["s3:ListAllMyBuckets"])),
        DurationSeconds=900,
    )

    fed_user = narrow["FederatedUser"]
    assert fed_user["Arn"] == f"arn:aws:sts::{account}:federated-user/{fed_name}", (
        "GetFederationToken.FederatedUser.Arn must have the sts federated-user form; got "
        f"{fed_user['Arn']!r}"
    )
    packed = narrow.get("PackedPolicySize")
    assert isinstance(packed, int) and 1 <= packed <= 100, (
        "GetFederationToken must report PackedPolicySize as a 1..100 percentage whenever a "
        f"Policy is supplied; got {packed!r} -- a missing value means the policy was never packed"
    )
    assert narrow["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        "a federation token's access key id must be in the ASIA class; got prefix "
        f"{narrow['Credentials']['AccessKeyId'][:4]!r}"
    )

    _wait_creds_active(narrow["Credentials"])
    narrow_s3 = _client_with_credentials("s3", narrow["Credentials"])

    # --- POSITIVE CONTROL: the one action the policy allows must work.
    _poll_allowed(
        lambda: narrow_s3.list_buckets(),
        what="federated session s3:ListAllMyBuckets allowed by the supplied Policy",
    )

    # --- Break exactly one thing: an s3 action the policy does NOT allow, on a bucket that
    # DOES exist and that the caller owns, so the authorization decision is actually reached.
    denied = _poll_denied(
        lambda: narrow_s3.get_bucket_location(Bucket=target_bucket), "AccessDenied",
        what="federated session s3:GetBucketLocation excluded by the supplied Policy",
    )
    assert denied[0] == "AccessDenied", (
        "GetFederationToken's Policy must cap the federated session: GetBucketLocation on "
        f"{target_bucket} returned {denied!r} instead of AccessDenied. The caller that minted "
        "this token owns that bucket, so anything other than AccessDenied means the Policy was "
        "ignored entirely"
    )
    assert denied[1] == _denied_message("s3:GetBucketLocation"), denied[1]
    # A second excluded action, to prove the cap is the policy's action list and not a
    # GetBucketLocation special case.
    denied_tagging = _poll_denied(
        lambda: narrow_s3.get_bucket_tagging(Bucket=target_bucket), "AccessDenied",
        what="federated session s3:GetBucketTagging excluded by the supplied Policy",
    )
    assert denied_tagging[0] == "AccessDenied", (
        "GetFederationToken's Policy must cap the federated session for a second, distinct "
        f"action: s3:GetBucketTagging on {target_bucket} returned {denied_tagging!r} instead of "
        "AccessDenied, so the cap is not the policy's action list"
    )
    assert denied_tagging[1] == _denied_message("s3:GetBucketTagging"), denied_tagging[1]

    # --- Widen ONLY the policy on a second token and the same call must now SUCCEED and return
    # the bucket's real location, proving the AccessDenied above came from the policy and not
    # from the caller lacking s3 permissions or the bucket being unreachable.
    broad = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-behav-fed-"),
        Policy=json.dumps(_allow(["s3:*"])),
        DurationSeconds=900,
    )
    _wait_creds_active(broad["Credentials"])
    broad_s3 = _client_with_credentials("s3", broad["Credentials"])
    _poll_allowed(
        lambda: broad_s3.get_bucket_location(Bucket=target_bucket),
        what="federated session s3:GetBucketLocation permitted by a broad Policy",
    )
    located = broad_s3.get_bucket_location(Bucket=target_bucket)
    assert located.get("LocationConstraint") == ctx.region, (
        "control leg failed: with a Policy allowing s3:* the same GetBucketLocation must succeed "
        f"and report the bucket's region {ctx.region!r}; got {located!r}"
    )

    # --- The bucket NAME is resolved before any authorization decision: against a bucket that
    # exists nowhere, BOTH sessions get NoSuchBucket -- the narrow one never even reaches the
    # policy. This is why the discriminating call above has to target a real bucket.
    narrow_absent = _error(lambda: narrow_s3.get_bucket_location(Bucket=absent_bucket))
    broad_absent = _error(lambda: broad_s3.get_bucket_location(Bucket=absent_bucket))
    assert narrow_absent == ("NoSuchBucket", "The specified bucket does not exist"), (
        "S3 must resolve a nonexistent bucket name before authorizing, so even the capped "
        f"session sees NoSuchBucket for {absent_bucket}; got {narrow_absent!r}"
    )
    assert broad_absent == ("NoSuchBucket", "The specified bucket does not exist"), (
        "S3 must resolve a nonexistent bucket name before authorizing for the broad session too, "
        f"so it should also see NoSuchBucket for {absent_bucket}; got {broad_absent!r}"
    )

    # --- and the narrow session is still capped.
    still = _poll_denied(
        lambda: narrow_s3.get_bucket_location(Bucket=target_bucket), "AccessDenied",
        what="narrow federated session (still capped)",
    )
    assert still == ("AccessDenied", _denied_message("s3:GetBucketLocation")), (
        "the narrow federated session must remain capped after the broad session's success "
        f"proved the target reachable; got {still!r} instead of AccessDenied for {target_bucket}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
