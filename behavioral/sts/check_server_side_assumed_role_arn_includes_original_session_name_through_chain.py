"""server-side-assumed-role-arn-includes-original-session-name-through-chain."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-assumed-role-arn-includes-original-session-name-through-chain"
GROUP = "server-side"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each hop of a role chain gets a server-generated AssumedRoleUser.Arn embedding THAT
    hop's own RoleSessionName -- the second hop's Arn reflects its own session name, not the
    first hop's, even though the underlying credentials originated from the first hop."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    partition = sts.get_caller_identity()["Arn"].split(":")[1]

    role_a_name = ctx.unique_name("sim2real-chainarn-a-")
    role_b_name = ctx.unique_name("sim2real-chainarn-b-")

    trust_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{partition}:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_a_arn = iam.create_role(
        RoleName=role_a_name,
        AssumeRolePolicyDocument=json.dumps(trust_a),
        Tags=_managed_tags(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_a_name))

    perm_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": f"arn:{partition}:iam::{account_id}:role/{role_b_name}",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_a_name, PolicyName="assume-b", PolicyDocument=json.dumps(perm_a))

    trust_b = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": role_a_arn}, "Action": "sts:AssumeRole"}],
    }
    role_b_arn = _poll_until(
        probe=lambda: _try_create_role_with_principal(
            iam, role_b_name, json.dumps(trust_b), Tags=_managed_tags()
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_b_name))

    hop1_session_name = ctx.unique_name("hop1session-")
    hop2_session_name = ctx.unique_name("hop2session-")
    assert hop1_session_name != hop2_session_name, (hop1_session_name, hop2_session_name)

    session1 = _poll_until(
        probe=lambda: _try_assume(sts, role_a_arn, hop1_session_name),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    expected_arn1 = f"arn:{partition}:sts::{account_id}:assumed-role/{role_a_name}/{hop1_session_name}"
    assert session1["AssumedRoleUser"]["Arn"] == expected_arn1, (
        f"expected {expected_arn1}, AssumeRole returned {session1['AssumedRoleUser']['Arn']!r}"
    )

    sts_hop1 = _client_from_creds(ctx, "sts", session1["Credentials"])
    # Independent read at the hop-1 destination: GetCallerIdentity, not AssumeRole's own
    # response, must agree that this session really is role A's, under hop1's session name.
    ident1 = sts_hop1.get_caller_identity()
    assert ident1["Arn"] == expected_arn1, (
        f"expected {expected_arn1}, GetCallerIdentity on hop-1 session returned {ident1['Arn']!r}"
    )

    session2 = _poll_until(
        probe=lambda: _try_assume(sts_hop1, role_b_arn, hop2_session_name),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    expected_arn2 = f"arn:{partition}:sts::{account_id}:assumed-role/{role_b_name}/{hop2_session_name}"
    assert session2["AssumedRoleUser"]["Arn"] == expected_arn2, (
        f"expected {expected_arn2}, AssumeRole returned {session2['AssumedRoleUser']['Arn']!r}"
    )

    sts_hop2 = _client_from_creds(ctx, "sts", session2["Credentials"])
    # Terminal assertion: an independent read (GetCallerIdentity, a different operation than
    # the AssumeRole that minted the session) at the destination -- not the mutating call's
    # own response -- confirms hop 2's Arn embeds ITS OWN session name, not hop 1's.
    ident2 = sts_hop2.get_caller_identity()
    assert ident2["Arn"] == expected_arn2, (
        f"expected {expected_arn2}, GetCallerIdentity on hop-2 session returned {ident2['Arn']!r}"
    )
    assert hop1_session_name not in ident2["Arn"], (
        f"hop-1 session name {hop1_session_name!r} leaked into hop-2 identity {ident2['Arn']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _try_assume(sts_client, role_arn, session_name, **kwargs):
    try:
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _try_create_role_with_principal(iam, role_name, trust_doc_json, Tags=None):
    try:
        return iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust_doc_json, Tags=Tags or []
        )["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "MalformedPolicyDocument":
            return None
        raise


def _managed_tags():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-chainarn"},
    ]


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
