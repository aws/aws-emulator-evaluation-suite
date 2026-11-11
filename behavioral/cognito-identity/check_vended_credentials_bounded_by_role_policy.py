"""vended-credentials-bounded-by-role-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vended-credentials-bounded-by-role-policy"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

# A GetCredentialsForIdentity session is bounded by TWO ceilings, not one, and the denial message
# says which ceiling stopped the call:
#   * the mapped role's identity-based policy -> "because no identity-based policy allows ..."
#   * an AWS-injected SESSION policy the caller never wrote and cannot see, which no role-policy
#     grant can widen -> "because no session policy allows ..."
#   * and Cognito Identity's own control plane refuses vended sessions outright, with neither
#     wording -> "These credentials are not valid for accessing this resource"
SESSION_NAME = "CognitoIdentityCredentials"
MSG_NO_SESSION_POLICY = "because no session policy allows"
IDENTITY_POLICY = "identity-based policy"
SESSION_POLICY = "session policy"
MSG_NOT_VALID_HERE = "These credentials are not valid for accessing this resource"
# s3:ListAllMyBuckets is the grantable probe action: read-only, resource-free, and inside the
# injected session policy's ceiling. iam:ListRoles is the ungrantable one, outside it.
GRANTABLE_ACTION = "s3:ListAllMyBuckets"
UNGRANTABLE_ACTION = "iam:ListRoles"
CONTROL_PLANE_ACTION = "cognito-identity:ListIdentityPools"
# A brand-new role's first vended session is occasionally rejected by STS for a few seconds
# ("The security token included in the request is invalid") before it becomes usable.
_TRANSIENT_SESSION = ("InvalidClientTokenId",)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _set_roles(ci, pool_id, roles, role_mappings=None, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    kwargs = {"IdentityPoolId": pool_id, "Roles": roles}
    if role_mappings is not None:
        kwargs["RoleMappings"] = role_mappings
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """Build a client signed with the vended temporary credentials."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _vend_guest_credentials(ci, ctx, pool_id):
    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="GetCredentialsForIdentity to vend guest credentials",
    )["Credentials"]
    return identity_id, creds


def _denial(fn, what):
    """Call fn(); return (Code, Message) when it is refused, and raise when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must be refused, but the call succeeded")


def _denied_message(principal, action, ceiling, resource=None):
    """The exact AccessDenied wording for `principal` refused `action` by a missing `ceiling`."""
    on_resource = f" on resource: {resource}" if resource else ""
    return (
        f"User: {principal} is not authorized to perform: {action}{on_resource} because no "
        f"{ceiling} allows the {action} action"
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Vended credentials carry only the mapped role's permissions: an ungranted call is denied and
    works once granted, an action outside Cognito's injected session policy stays denied, and
    Cognito Identity's own control plane refuses vended sessions whatever the role policy allows.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = _create_identity_pool(ci, ctx, allow_unauth=True)
    trust = _cognito_trust_policy(pool_id)
    unauth_name, unauth_arn = _create_role(iam, ctx, trust, "bounded")
    _, auth_arn = _create_role(iam, ctx, trust, "auth")
    _set_roles(ci, pool_id, {"authenticated": auth_arn, "unauthenticated": unauth_arn})

    # The role has a trust policy and no permission policy at all.
    _, creds = _vend_guest_credentials(ci, ctx, pool_id)
    sts_client = _client_from_credentials(ctx, "sts", creds)
    identity = _poll_until(
        lambda: sts_client.get_caller_identity(),
        lambda r: bool(r.get("Arn")),
        timeout_s=120.0,
        description="the vended session to become usable by STS",
    )
    caller_arn = identity["Arn"]
    partition = caller_arn.split(":")[1]
    account = identity["Account"]
    assert f":assumed-role/{unauth_name}/{SESSION_NAME}" in caller_arn, (
        f"vended credentials must be a session of the unauthenticated role {unauth_name} named "
        f"{SESSION_NAME}, got {caller_arn}"
    )

    # ---- Denial 1: the role's own policy allows nothing, so a plain read is refused, and the
    # message names the principal, the action, and WHICH policy was missing.
    s3_denied = _client_from_credentials(ctx, "s3", creds)
    code, msg = _denial(
        lambda: s3_denied.list_buckets(),
        f"{GRANTABLE_ACTION} under credentials for a role with no permission policy",
    )
    assert code == "AccessDenied", (
        f"expected an access-denied error for an unpermitted action under vended credentials, "
        f"got {code!r}: {msg!r}"
    )
    expected = _denied_message(caller_arn, GRANTABLE_ACTION, IDENTITY_POLICY)
    assert msg == expected, (
        f"with no policy on the role, the refusal must name the vended session, the action and "
        f"the missing identity-based policy: expected {expected!r}, got {msg!r}"
    )

    # ---- Denial 2: the same, on Cognito Identity's own control plane.
    cognito_denied = _client_from_credentials(ctx, "cognito-identity", creds)
    cp_code, cp_msg = _denial(
        lambda: cognito_denied.list_identity_pools(MaxResults=1),
        f"{CONTROL_PLANE_ACTION} under credentials for a role with no permission policy",
    )
    assert cp_code == "AccessDeniedException", (
        f"the control-plane refusal starts out as an access denial, got {cp_code!r}: {cp_msg!r}"
    )
    expected = _denied_message(
        caller_arn,
        CONTROL_PLANE_ACTION,
        IDENTITY_POLICY,
        f"arn:{partition}:cognito-identity:{ctx.region}:{account}:identitypool/",
    )
    assert cp_msg == expected, (
        f"the control-plane refusal starts out as the same identity-based-policy denial: "
        f"expected {expected!r}, got {cp_msg!r}"
    )

    # ---- Change exactly one thing: grant all three actions on the role.
    policy_name = "sim2real-behav-vended-grant"
    iam.put_role_policy(
        RoleName=unauth_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [GRANTABLE_ACTION, UNGRANTABLE_ACTION, CONTROL_PLANE_ACTION],
                "Resource": "*",
            }],
        }),
    )
    # Registered after delete_role so LIFO cleanup removes the inline policy first.
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=unauth_name, PolicyName=policy_name)
    )

    # The grant reaches the vended session: the denial above was real authorization, not a
    # blanket refusal of vended credentials.
    #
    # A fresh identity and session are vended on every attempt: policy propagation to a vended
    # session is usually ~10s, but one reused session can keep the pre-grant answer for minutes.
    granted_creds = {}

    def _attempt(service, call):
        _, fresh = _vend_guest_credentials(ci, ctx, pool_id)
        granted_creds.clear()
        granted_creds.update(fresh)
        client = _client_from_credentials(ctx, service, fresh)
        try:
            return {"ok": call(client)}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return {"code": err.get("Code"), "message": err.get("Message") or ""}

    allowed = _poll_until(
        lambda: _attempt("s3", lambda c: c.list_buckets()),
        lambda r: "ok" in r,
        timeout_s=300.0,
        interval_s=10.0,
        description="the granted inline policy to take effect for a vended session",
    )["ok"]
    assert isinstance(allowed["Buckets"], list), (
        f"{GRANTABLE_ACTION} must succeed once granted, got {allowed!r}"
    )

    # ---- The session policy ceiling: iam:ListRoles is granted on the role and STILL refused, and
    # the refusal reason MOVES from the identity-based policy to a session policy the caller never
    # wrote. That is Cognito attaching its own scope-down policy to every vended session, and it is
    # the assertion an emulator that hands back account-wide credentials cannot pass.
    ceiling_msg = _poll_until(
        lambda: _attempt("iam", lambda c: c.list_roles(MaxItems=1)),
        lambda r: MSG_NO_SESSION_POLICY in r.get("message", ""),
        timeout_s=180.0,
        interval_s=10.0,
        description=(
            f"{UNGRANTABLE_ACTION} to be refused by the injected session policy rather than the "
            f"role policy"
        ),
    )["message"]
    # Every vended session of this role carries the same session name, so its ARN is caller_arn.
    expected = _denied_message(
        caller_arn, UNGRANTABLE_ACTION, SESSION_POLICY, f"arn:{partition}:iam::{account}:role/"
    )
    assert ceiling_msg == expected, (
        f"{UNGRANTABLE_ACTION} is granted on the role, so the only thing that can still refuse it "
        f"is the injected session policy: expected {expected!r}, got {ceiling_msg!r}"
    )

    # ---- And Cognito Identity's control plane refuses vended sessions with neither wording: no
    # IAM grant lifts it, so this is a service-level guard, not an authorization decision.
    cognito_granted = _client_from_credentials(ctx, "cognito-identity", granted_creds)
    guard_code, guard_msg = _denial(
        lambda: cognito_granted.list_identity_pools(MaxResults=1),
        f"{CONTROL_PLANE_ACTION} under vended credentials whose role policy allows it",
    )
    assert guard_code == "AccessDeniedException", (
        f"{CONTROL_PLANE_ACTION} must stay refused under vended credentials even when the role "
        f"policy allows it, got {guard_code!r}"
    )
    assert guard_msg == MSG_NOT_VALID_HERE, (
        f"the guard has its own message, distinct from both policy denials, and it is the whole "
        f"message: expected {MSG_NOT_VALID_HERE!r}, got {guard_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
