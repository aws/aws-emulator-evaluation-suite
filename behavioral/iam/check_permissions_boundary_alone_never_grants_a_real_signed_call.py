"""permissions-boundary-alone-never-grants-a-real-signed-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permissions-boundary-alone-never-grants-a-real-signed-call"
GROUP = "permissions_boundaries"
SERVICES = ["iam"]

_BASELINE = "sim2real-behav-bound-nogrant-baseline"
_GRANT = "sim2real-behav-bound-nogrant-grant"
_SUBJECT = "iam:ListAccessKeys"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A boundary is a ceiling, never a grant: an action only the boundary allows is AccessDenied
    (simulator: implicitDeny, AllowedByPermissionsBoundary True), succeeds once an identity policy
    allows it, and is refused again once that identity policy is deleted.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
    """
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-bnogrant-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    # The baseline identity policy grants ONE unrelated action and never the subject action. It is
    # the credential-health control: without it a refusal below could mean "this key does not work".
    iam.put_user_policy(
        UserName=user,
        PolicyName=_BASELINE,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:ListUserTags",
                "Resource": user_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_BASELINE))

    # The boundary permits BOTH the baseline action and the subject action, so it can never be the
    # thing that blocks anything in this check.
    boundary_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-bnogrant-bound-"),
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:ListUserTags", _SUBJECT],
                "Resource": "*",
            }],
        }),
        Description=f"sim2real {CHECK}",
        Tags=_MARK,
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=boundary_arn))

    iam.put_user_permissions_boundary(UserName=user, PermissionsBoundary=boundary_arn)
    ctx.on_cleanup(lambda: _drop_boundary(iam, user))
    attached = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert attached.get("PermissionsBoundaryArn") == boundary_arn, (
        f"the boundary must be observably attached before anything is concluded from its absence of "
        f"effect: expected {boundary_arn!r}, GetUser reported {attached!r}"
    )

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _signing_as(ctx, "iam", key)

    # --- Control: the baseline action works, so the credential and the authorizer are healthy for
    #     this principal, and the boundary is not blanket-blocking.
    ready = _poll(
        lambda: _outcome(lambda: as_user.list_user_tags(UserName=user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the baseline grant, permitted by both documents, becomes effective",
    )
    assert ready == "OK", (
        f"the baseline action is Allowed by the identity policy AND by the boundary, so it must "
        f"succeed -- otherwise the refusal below is about the credential, not about the boundary; "
        f"expected 'OK', got {ready!r}"
    )

    # --- The claim: only the BOUNDARY allows the subject action. Nothing grants it.
    # A fresh key can still be unknown to the replica serving this call (InvalidClientTokenId)
    # even after the control succeeded, so wait out only that code; a success still raises.
    ungranted, ungranted_message = _poll(
        lambda: _rejected(lambda: as_user.list_access_keys(UserName=user)),
        lambda r: r[0] != "InvalidClientTokenId",
        timeout_s=60,
        interval_s=3,
        description="the minted key is recognized for the ungranted call",
    )
    assert ungranted == "AccessDenied", (
        f"{_SUBJECT} is Allowed by the attached boundary and by NO identity policy, so the real "
        f"signed call must be refused with exactly AccessDenied; got {ungranted!r} -- an emulator "
        f"that unions the boundary into the principal's effective permissions succeeds here and has "
        f"inverted the feature"
    )
    expected = _with_authorization_details(
        f"User: {user_arn} is not authorized to perform: {_SUBJECT} on resource: user {user} "
        f"because no identity-based policy allows the {_SUBJECT} action",
        ungranted_message,
    )
    assert ungranted_message == expected, (
        f"expected message {expected!r}, got {ungranted_message!r}"
    )

    # --- The simulator must say the same contradictory-looking thing: the boundary permits it, and
    #     it is denied anyway.
    detail = _boundary_detail(iam, user_arn, _SUBJECT, user_arn)
    assert detail["decision"] == "implicitDeny", (
        f"with no identity policy granting {_SUBJECT}, the simulator must report 'implicitDeny' "
        f"regardless of what the boundary allows; got {detail['decision']!r}"
    )
    assert detail["allowed_by_boundary"] is True, (
        f"the boundary DOES allow {_SUBJECT}, so AllowedByPermissionsBoundary must be True even "
        f"though the overall decision is a deny -- that pairing is the whole claim; got "
        f"{detail['allowed_by_boundary']!r}"
    )

    # --- Break exactly one thing: add an identity policy that grants the subject action. The
    #     boundary is untouched. If the call now works, the earlier refusal was "no grant" and not
    #     "the boundary blocked it".
    iam.put_user_policy(
        UserName=user,
        PolicyName=_GRANT,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": _SUBJECT, "Resource": user_arn}],
        }),
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, user, _GRANT))
    still_bounded = iam.get_user(UserName=user)["User"].get("PermissionsBoundary", {})
    assert still_bounded.get("PermissionsBoundaryArn") == boundary_arn, (
        f"the boundary must still be attached while the grant is added, so the two legs differ in "
        f"exactly one document: expected {boundary_arn!r}, GetUser reported {still_bounded!r}"
    )
    granted = _poll(
        lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="an identity-policy grant inside the boundary permits the refused call",
    )
    assert granted == "OK", (
        f"with an identity policy granting {_SUBJECT} and the same boundary still attached, the "
        f"identical real signed call must succeed; expected 'OK', got {granted!r} -- if it does not, "
        f"the target is treating the boundary as a deny list rather than a ceiling"
    )

    # --- And removing the grant restores the refusal, with the boundary never having moved.
    iam.delete_user_policy(UserName=user, PolicyName=_GRANT)
    inline = [
        n
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user)
        for n in page["PolicyNames"]
    ]
    assert inline == [_BASELINE], (
        f"only the grant may be gone -- the baseline policy must survive so the credential-health "
        f"control still holds; expected [{_BASELINE!r}], the paginated ListUserPolicies reports "
        f"{inline!r}"
    )
    again = _poll(
        lambda: _outcome(lambda: as_user.list_access_keys(UserName=user)),
        lambda o: o == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="removing the identity grant restores the refusal while the boundary is unchanged",
    )
    assert again == "AccessDenied", (
        f"with the identity grant deleted and only the boundary left permitting {_SUBJECT}, the call "
        f"must be refused with exactly AccessDenied again; got {again!r}"
    )
    final_baseline = _outcome(lambda: as_user.list_user_tags(UserName=user))
    assert final_baseline == "OK", (
        f"the baseline action must still work at the end, proving the final refusal is scoped to the "
        f"ungranted action and not a credential that stopped working; expected 'OK', got "
        f"{final_baseline!r}"
    )


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code; callers poll it or assert an exact value."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected(fn):
    """(code, message) of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code") or "NO_ERROR_CODE", error.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` plus a pointer to the per-request authorization id, the
    only part read back from the message. The console link names us-east-1 because IAM's global
    endpoint signs every request there."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline. RAISES on timeout -- never returns its last value on failure."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the owner of ``key``, on this ctx's endpoint."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _boundary_detail(iam, source_arn, action, resource_arn):
    """The simulator's decision AND its stated boundary attribution for one action."""
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=[action], ResourceArns=[resource_arn]
    )["EvaluationResults"]
    assert results, (
        f"SimulatePrincipalPolicy must return an evaluation result for {action!r}; "
        f"EvaluationResults was empty"
    )
    result = results[0]
    return {
        "decision": result["EvalDecision"],
        "allowed_by_boundary": result.get("PermissionsBoundaryDecisionDetail", {}).get(
            "AllowedByPermissionsBoundary"
        ),
    }


def _drop_boundary(iam, user):
    """Teardown-only: tolerate the boundary already being detached. Scoped to this one user."""
    try:
        iam.delete_user_permissions_boundary(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _drop_user_policy(iam, user, policy_name):
    """Teardown-only: tolerate the inline policy already being deleted by the body."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
