"""server-side-source-identity-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-source-identity-missing-permission-rejected"
GROUP = "server-side"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Chaining a session with a SourceIdentity into a role whose trust policy lacks
    sts:SetSourceIdentity is AccessDenied with its exact message; a sibling role granting
    it succeeds and carries the source identity through."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_a_name = ctx.unique_name("sim2real-srcid-a-")
    role_bad_name = ctx.unique_name("sim2real-srcid-bad-")
    role_good_name = ctx.unique_name("sim2real-srcid-good-")

    trust_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            }
        ],
    }
    role_a_arn = iam.create_role(
        RoleName=role_a_name,
        AssumeRolePolicyDocument=json.dumps(trust_a),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_a_name))

    perm_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Resource": [
                    f"arn:aws:iam::{account_id}:role/{role_bad_name}",
                    f"arn:aws:iam::{account_id}:role/{role_good_name}",
                ],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_a_name, PolicyName="assume-targets", PolicyDocument=json.dumps(perm_a))

    # Bad target: trust policy grants only sts:AssumeRole -- NOT sts:SetSourceIdentity.
    trust_bad = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": role_a_arn}, "Action": "sts:AssumeRole"}
        ],
    }
    role_bad_arn = _poll_until(
        probe=lambda: _try_create_role_with_principal(
            iam, role_bad_name, json.dumps(trust_bad), _tags_kv()
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_bad_name))

    # Good (control) target: trust policy grants both actions.
    trust_good = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_a_arn},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            }
        ],
    }
    role_good_arn = _poll_until(
        probe=lambda: _try_create_role_with_principal(
            iam, role_good_name, json.dumps(trust_good), _tags_kv()
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_good_name))

    source_identity = ctx.unique_name("bob-")
    hop1_session_name = ctx.unique_name("hop1-")
    session1 = _poll_until(
        probe=lambda: _try_assume(
            sts, role_a_arn, hop1_session_name, SourceIdentity=source_identity
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session1["SourceIdentity"] == source_identity, (
        f"hop1 AssumeRole must echo the SourceIdentity it recorded; got {session1['SourceIdentity']!r}"
    )
    sts_hop1 = _client_from_creds(ctx, "sts", session1["Credentials"])

    # Negative: chaining into the bad target is rejected.
    code, message = _error(
        lambda: sts_hop1.assume_role(RoleArn=role_bad_arn, RoleSessionName=ctx.unique_name("hop2bad-"))
    )
    assert code == "AccessDenied", (
        f"chaining into a target whose trust policy grants sts:AssumeRole but not "
        f"sts:SetSourceIdentity must be rejected with AccessDenied; got {code!r}"
    )
    # AWS names sts:AssumeRole in the refusal, not the missing sts:SetSourceIdentity grant.
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_a_name}/{hop1_session_name} is not "
        f"authorized to perform: sts:AssumeRole on resource: {role_bad_arn}"
    )
    assert message == expected_message, (
        f"unexpected refusal message: expected {expected_message!r}, got {message!r}"
    )

    # Positive control: the sibling role that grants sts:SetSourceIdentity.
    session2 = _poll_until(
        probe=lambda: _try_assume(sts_hop1, role_good_arn, ctx.unique_name("hop2good-")),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session2["SourceIdentity"] == source_identity, (
        f"the sibling target's trust policy grants sts:SetSourceIdentity, so the chained call must "
        f"succeed and carry the source identity through unchanged; got {session2['SourceIdentity']!r}"
    )

    # Independent read: session2 really belongs to role_good.
    sts_hop2 = _client_from_creds(ctx, "sts", session2["Credentials"])
    ident2 = sts_hop2.get_caller_identity()
    assert role_good_name in ident2["Arn"], (
        f"the chained session must belong to role_good; got caller identity {ident2['Arn']!r}"
    )


def _tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-srcid"},
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """The (Code, Message) of the error fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _try_assume(sts_client, role_arn, session_name, **kwargs):
    try:
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _try_create_role_with_principal(iam, role_name, trust_doc_json, tags_kv):
    try:
        return iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust_doc_json, Tags=tags_kv
        )["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "MalformedPolicyDocument":
            return None
        raise


def _delete_role(iam, role_name) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_from_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
