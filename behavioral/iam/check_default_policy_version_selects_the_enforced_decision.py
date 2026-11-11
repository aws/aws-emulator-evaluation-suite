"""default-policy-version-selects-the-enforced-decision."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-policy-version-selects-the-enforced-decision"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})


# An AccessDenied ends with a pointer to a server-minted, per-request authorization id, given
# twice (in a console URL and on its own); every other character is pinned.
_AUTHZ_TAIL = (
    r"\. Go to https://[a-z0-9-]+\.console\.aws\.amazon\.com/iam/home\?region=[a-z0-9-]+"
    r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
    r"API with the following authorization id: \1"
)


def _expected_denial(message, head):
    """``head`` followed by the authorization-details pointer that ends ``message``: the pointer's
    region and per-request authorization id are the only parts read back from it."""
    found = re.search(_AUTHZ_TAIL + r"\Z", message or "")
    return head + (found.group(0) if found else ". Go to <authorization-details pointer>")


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


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


def _versions(iam, policy_arn):
    """Every version of the policy, paginated, as {VersionId: IsDefaultVersion}."""
    out = {}
    for page in iam.get_paginator("list_policy_versions").paginate(PolicyArn=policy_arn):
        for v in page.get("Versions", []):
            out[v["VersionId"]] = v["IsDefaultVersion"]
    return out


def _restore_v1_and_drop_v2(iam, policy_arn, v1, v2):
    """Undo the create of v2. A non-default version is deletable; the default one is not, so the
    default is moved back to v1 first. Tolerates the body having already done both."""
    try:
        iam.set_default_policy_version(PolicyArn=policy_arn, VersionId=v1)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchEntity", "InvalidInput"):
            raise
    try:
        iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v2)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _denial_message(fn):
    """Error.Message of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "plane:control",
    "cap:c1",
)
def run(ctx) -> None:
    """Only the default policy version is enforced: making a version without the grant the default makes
    the real signed call fail with AccessDenied and the exact message, moving the default back restores
    it, and the version list then holds v1 as default and v2 with its own statement unchanged."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-defver-user-")

    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    v1_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn}],
    })
    policy = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-defver-pol-"),
        PolicyDocument=v1_document,
        Description="sim2real default-policy-version enforcement check",
        Tags=[{"Key": "sim2real", "Value": "default-policy-version-selects-the-enforced-decision"}],
    )["Policy"]
    policy_arn = policy["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    v1 = policy["DefaultVersionId"]

    iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user, PolicyArn=policy_arn))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    )
    as_user = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # --- Positive control on v1: the grant is live. IAM replicates the key AND the attachment
    #     per-replica and reports neither as effective, so the wait is a bounded poll on the granted
    #     call itself; it raises rather than skipping if it never converges.
    on_v1 = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="v1's grant becomes effective for the minted key on a real signed call",
    )
    assert on_v1 == "UNEXPECTED_SUCCESS", (
        f"v1 grants iam:GetUser and is the default, so the real signed call must succeed; got "
        f"{on_v1!r}"
    )

    # --- Break exactly one thing: a v2 that omits iam:GetUser, promoted to default.
    v2_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:GetAccountSummary", "Resource": "*"},
        ],
    })
    v2 = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=v2_document, SetAsDefault=True
    )["PolicyVersion"]["VersionId"]
    ctx.on_cleanup(lambda: _restore_v1_and_drop_v2(iam, policy_arn, v1, v2))

    default_now = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    assert default_now == v2, (
        f"the default flag must observably have MOVED before its effect is used: GetPolicy reports "
        f"{default_now!r}, expected {v2!r}"
    )

    on_v2 = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="promoting v2 to default withdraws the grant on the real signed call",
    )
    assert on_v2 == "AccessDenied", (
        f"v2 is the default and omits iam:GetUser, so the real signed call must be refused with "
        f"exactly AccessDenied; got {on_v2!r} -- an emulator enforcing the union of all versions, "
        f"or always v1, fails here"
    )
    on_v2_msg = _denial_message(lambda: as_user.get_user(UserName=user))
    assert "is not authorized to perform: iam:GetUser" in on_v2_msg, (
        f"the denial must name the refused action iam:GetUser; got {on_v2_msg!r}"
    )
    assert on_v2_msg == _expected_denial(on_v2_msg, (
        f"User: {user_arn} is not authorized to perform: iam:GetUser on resource: user {user} "
        "because no identity-based policy allows the iam:GetUser action"
    )), f"expected the exact AccessDenied message AWS returns, got {on_v2_msg!r}"

    # --- Reverse it: the default flag is a pointer, and moving it back restores the outcome.
    iam.set_default_policy_version(PolicyArn=policy_arn, VersionId=v1)
    back_on_v1 = _poll(
        lambda: _error_code(lambda: as_user.get_user(UserName=user)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="moving the default back to v1 restores the grant",
    )
    assert back_on_v1 == "UNEXPECTED_SUCCESS", (
        f"restoring v1 as the default must restore the real signed call; got {back_on_v1!r}"
    )

    # --- The rollback moved a pointer; it did not rewrite history.
    versions = _versions(iam, policy_arn)
    assert set(versions) == {v1, v2}, (
        f"both versions must still exist after the rollback: the paginated list reports "
        f"{sorted(versions)!r}, expected {sorted([v1, v2])!r}"
    )
    assert versions[v1] is True and versions[v2] is False, (
        f"exactly v1 must carry the default flag after the rollback; the list reports "
        f"{versions!r}"
    )
    kept = iam.get_policy_version(PolicyArn=policy_arn, VersionId=v2)["PolicyVersion"]["Document"]
    kept_actions = [s["Action"] for s in _as_statements(kept)]
    assert kept_actions == ["iam:GetAccountSummary"], (
        f"v2's document must be unchanged by the rollback: expected ['iam:GetAccountSummary'], got "
        f"{kept_actions!r}"
    )


def _as_statements(document):
    """GetPolicyVersion returns the document URL-encoded or already decoded, depending on the
    client's decoding; normalise both to a statement list rather than doing string surgery."""
    import urllib.parse

    if isinstance(document, str):
        document = json.loads(urllib.parse.unquote(document))
    statements = document["Statement"]
    return statements if isinstance(statements, list) else [statements]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
