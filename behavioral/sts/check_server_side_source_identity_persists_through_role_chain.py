"""server-side-source-identity-persists-through-role-chain."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-source-identity-persists-through-role-chain"
GROUP = "server-side"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """aws:SourceIdentity set on the first AssumeRole of a chain is carried unchanged onto a
    second, chained AssumeRole call even though the second hop never re-specifies it -- the
    value is enforced/propagated server-side, not supplied by the client at later hops."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_a_name = ctx.unique_name("sim2real-srcid-a-")
    role_b_name = ctx.unique_name("sim2real-srcid-b-")

    # Trust root A: any principal in this account may assume it and set a source identity
    # (the calling test identity already has sts:AssumeRole via its own permissions policy).
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
    role_a_arn = iam.create_role(RoleName=role_a_name, AssumeRolePolicyDocument=json.dumps(trust_a))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_a_name))

    # Role A needs its own permission to assume + carry source identity into role B.
    perm_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Resource": f"arn:aws:iam::{account_id}:role/{role_b_name}",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_a_name, PolicyName="assume-b", PolicyDocument=json.dumps(perm_a))

    trust_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_a_arn},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            }
        ],
    }
    # A trust policy that names a just-created role as Principal can transiently be rejected
    # ("Invalid principal in policy") until IAM control-plane propagation completes. Retry.
    role_b_arn = _poll_until(
        probe=lambda: _try_create_role_with_principal(iam, role_b_name, json.dumps(trust_b)),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_b_name))

    source_identity = ctx.unique_name("alice-")

    session1 = _poll_until(
        probe=lambda: _try_assume(
            sts, role_a_arn, ctx.unique_name("hop1-"), SourceIdentity=source_identity
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session1["SourceIdentity"] == source_identity, (
        f"AssumeRole must echo the SourceIdentity it was given on hop 1; "
        f"expected {source_identity!r}, got {session1.get('SourceIdentity')!r}"
    )
    sts_hop1 = _client_from_creds(ctx, "sts", session1["Credentials"])

    # Second hop: chain into role B WITHOUT re-specifying SourceIdentity at all.
    session2 = _poll_until(
        probe=lambda: _try_assume(sts_hop1, role_b_arn, ctx.unique_name("hop2-")),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session2["SourceIdentity"] == source_identity, (
        "SourceIdentity must persist unchanged through a role chain without being resupplied"
    )

    # GetCallerIdentity on the hop-2 session confirms it is genuinely role B's session.
    sts_hop2 = _client_from_creds(ctx, "sts", session2["Credentials"])
    # Fresh session credentials can be refused with InvalidClientTokenId until they propagate.
    ident2 = _poll_until(
        probe=lambda: _try_caller_identity(sts_hop2),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
    )
    expected_prefix = f"arn:aws:sts::{account_id}:assumed-role/{role_b_name}/"
    assert ident2["Arn"].startswith(expected_prefix), (
        f"hop-2 GetCallerIdentity must be an assumed-role session for role B; "
        f"expected an Arn starting with {expected_prefix!r}, got {ident2['Arn']!r}"
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


def _try_create_role_with_principal(iam, role_name, trust_doc_json):
    try:
        return iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc_json)["Role"][
            "Arn"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] == "MalformedPolicyDocument":
            return None
        raise


def _try_caller_identity(sts_client):
    try:
        return sts_client.get_caller_identity()
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidClientTokenId":
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
