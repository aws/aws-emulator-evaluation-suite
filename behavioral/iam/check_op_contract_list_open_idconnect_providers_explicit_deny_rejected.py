"""op-contract-listOpenIDConnectProviders-explicit-deny-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listOpenIDConnectProviders-explicit-deny-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ALLOW = "sim2real-oidc-deny-allow-both"
_DENY = "sim2real-oidc-deny-list-oidc"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOpenIDConnectProviders lists both new providers and drops a deleted one (Get:
    exact NoSuchEntity); an explicit Deny makes the real signed call fail with
    AccessDenied while iam:ListRoles still works, and removing the Deny restores it."""
    iam = ctx.client("iam")

    provider_arns = []
    for i in range(2):
        url = f"https://{ctx.unique_name(f'sim2real-oidc-{i}-')}.example.com"
        arn = iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
        )["OpenIDConnectProviderArn"]
        provider_arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _delete_if_present(iam, a))

    both_present = _poll_until(
        lambda: {p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]},
        lambda arns: set(provider_arns) <= arns,
        timeout_s=20,
    )
    assert set(provider_arns) <= both_present, (
        f"expected both {provider_arns} present after the poll; got {sorted(both_present)}"
    )

    # deleting one provider removes exactly that ARN from the next real call
    removed_arn = provider_arns[0]
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=removed_arn)
    after_delete = _poll_until(
        lambda: {p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]},
        lambda arns: removed_arn not in arns,
        timeout_s=20,
    )
    assert removed_arn not in after_delete, f"expected {removed_arn} gone from {sorted(after_delete)}"
    assert provider_arns[1] in after_delete, (
        f"expected sibling provider {provider_arns[1]} to survive deletion of {removed_arn}; "
        f"got {sorted(after_delete)}"
    )
    # the delete also makes the ARN unusable, independent of the list read above
    try:
        gone = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=removed_arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"the deleted provider must be unreachable, but GetOpenIDConnectProvider returned {gone!r}")
    assert code == "NoSuchEntity", f"expected the deleted provider to be unreachable; got {code!r}"
    expected_message = f"OpenIDConnect Provider not found for arn {removed_arn}"
    assert message == expected_message, (
        f"the deleted provider's NoSuchEntity must carry AWS's exact message {expected_message!r}; "
        f"got {message!r}"
    )

    # --- an explicit Deny actually blocks the real signed call (not merely the simulator) ---
    user = ctx.unique_name("sim2real-oidc-deny-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user,
        PolicyName=_ALLOW,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:ListOpenIDConnectProviders", "iam:ListRoles"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_ALLOW))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # Positive control, captured BEFORE anything is broken: with only the Allow in place,
    # both the action under test and its sibling succeed for the freshly-minted principal.
    before_list = _poll(
        lambda: _error_code(lambda: as_user.list_open_id_connect_providers()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListOpenIDConnectProviders on a real signed call",
    )
    assert before_list == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListOpenIDConnectProviders must succeed; got {before_list!r}"
    )
    before_roles = _poll(
        lambda: _error_code(lambda: as_user.list_roles()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the Allow becomes effective for iam:ListRoles on a real signed call",
    )
    assert before_roles == "UNEXPECTED_SUCCESS", (
        f"with only the Allow in place the real signed ListRoles must succeed; got {before_roles!r}"
    )

    # Break exactly ONE thing: a second inline policy denying iam:ListOpenIDConnectProviders only.
    iam.put_user_policy(
        UserName=user,
        PolicyName=_DENY,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Deny", "Action": "iam:ListOpenIDConnectProviders", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, user))

    after_list = _poll(
        lambda: _error_code(lambda: as_user.list_open_id_connect_providers()),
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the explicit Deny takes effect on the real signed ListOpenIDConnectProviders",
    )
    assert after_list == "AccessDenied", (
        f"an explicit Deny naming iam:ListOpenIDConnectProviders must refuse the real signed call "
        f"with exactly AccessDenied; got {after_list!r}"
    )
    # message varies: AWS appends a per-request authorization id and console URL to this denial.
    # The stable part that names the refused action is graded.
    denied_msg = _denial_message(lambda: as_user.list_open_id_connect_providers())
    assert "is not authorized to perform: iam:ListOpenIDConnectProviders" in denied_msg, (
        f"the denial must name the refused action iam:ListOpenIDConnectProviders; got {denied_msg!r}"
    )

    # The Deny is SCOPED to the action it names -- an emulator that revokes everything fails here.
    after_roles = _poll(
        lambda: _error_code(lambda: as_user.list_roles()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the sibling action iam:ListRoles is unaffected by the Deny",
    )
    assert after_roles == "UNEXPECTED_SUCCESS", (
        f"the Deny names iam:ListOpenIDConnectProviders only, so iam:ListRoles must still succeed "
        f"for the same principal; got {after_roles!r} -- a Deny is not a blanket revoke"
    )

    # The simulator must agree, and must call it an EXPLICIT deny with the deny policy named.
    sim = _poll(
        lambda: _decisions(iam, user_arn, ["iam:ListOpenIDConnectProviders"]),
        lambda d: d.get("iam:ListOpenIDConnectProviders", {}).get("EvalDecision") == "explicitDeny",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the simulator reports explicitDeny for iam:ListOpenIDConnectProviders",
    )
    decision = sim["iam:ListOpenIDConnectProviders"]
    assert decision["EvalDecision"] == "explicitDeny", (
        f"with a Deny statement present the simulator must say 'explicitDeny', not "
        f"{decision['EvalDecision']!r}"
    )
    sources = {s.get("SourcePolicyId") for s in decision.get("MatchedStatements", [])}
    assert sources == {f"user_{user}_{_DENY}"}, (
        f"the deny must be attributed to the stored inline policy that carries it, and to nothing "
        f"else: expected {{{f'user_{user}_{_DENY}'!r}}}, got {sorted(s for s in sources if s)!r}"
    )

    # --- Reverse the one change: the effect must be reversible, so the middle state was caused by
    #     the Deny and not by drift.
    iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    restored = _poll(
        lambda: _error_code(lambda: as_user.list_open_id_connect_providers()),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="deleting the Deny restores the real signed ListOpenIDConnectProviders call",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"deleting the Deny must restore the Allow's grant on the real signed call; got {restored!r}"
    )


def _delete_if_present(iam, arn):
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _drop_deny(iam, user):
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_DENY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal, so the Deny is checked on the enforcement path.

    ``ctx.client(..., creds=...)`` keeps this target's endpoint, region and TLS settings.
    """
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _decisions(iam, source_arn, actions):
    results = iam.simulate_principal_policy(PolicySourceArn=source_arn, ActionNames=actions)[
        "EvaluationResults"
    ]
    return {r["EvalActionName"]: r for r in results}


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
