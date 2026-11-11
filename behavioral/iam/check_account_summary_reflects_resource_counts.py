"""account-summary-reflects-resource-counts."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-summary-reflects-resource-counts"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountSummary's SummaryMap counts and GetAccountAuthorizationDetails' entity lists are
    server-computed and change by exactly the expected delta as roles/users are created and
    deleted."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acctsum-role-")
    user_name = ctx.unique_name("sim2real-acctsum-user-")

    baseline = iam.get_account_summary()["SummaryMap"]
    base_roles, base_users = baseline["Roles"], baseline["Users"]

    trust_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=role_name)))
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_user(UserName=user_name)))

    # The poll's own terminal set ("something changed") is deliberately looser than the assertions
    # below it, so a timeout (nothing changed) and a wrong-delta (changed, but not by exactly 1)
    # are distinguishable failures instead of one bare AssertionError.
    after = _poll_until(
        lambda: iam.get_account_summary()["SummaryMap"],
        lambda m: m["Roles"] != base_roles or m["Users"] != base_users,
        timeout_s=30.0,
        desc="GetAccountSummary to notice the new role/user",
    )
    assert after["Roles"] == base_roles + 1, (
        f"expected Roles to increase by exactly 1 ({base_roles} -> {base_roles + 1}), got {after['Roles']}"
    )
    assert after["Users"] == base_users + 1, (
        f"expected Users to increase by exactly 1 ({base_users} -> {base_users + 1}), got {after['Users']}"
    )

    # GetAccountAuthorizationDetails is paginated and this account carries well over a page's
    # worth of roles (service-linked roles alone fill a page), so a single unpaginated call can
    # miss the new role/user purely on page ordering -- never mind eventual consistency.
    def _auth_details():
        role_arns, user_arns = {}, {}
        for page in iam.get_paginator("get_account_authorization_details").paginate(
            Filter=["Role", "User"]
        ):
            role_arns.update({r["RoleName"]: r["Arn"] for r in page["RoleDetailList"]})
            user_arns.update({u["UserName"]: u["Arn"] for u in page["UserDetailList"]})
        return role_arns, user_arns

    role_names, user_names = _poll_until(
        _auth_details,
        lambda pair: role_name in pair[0] and user_name in pair[1],
        timeout_s=60.0,
        desc="GetAccountAuthorizationDetails to list the new role/user",
    )
    assert role_names.get(role_name) == role_arn, (
        f"expected GetAccountAuthorizationDetails to list {role_name!r} with Arn {role_arn}, "
        f"got {role_names.get(role_name)!r}"
    )
    assert user_names.get(user_name) == user_arn, (
        f"expected GetAccountAuthorizationDetails to list {user_name!r} with Arn {user_arn}, "
        f"got {user_names.get(user_name)!r}"
    )

    iam.delete_role(RoleName=role_name)
    iam.delete_user(UserName=user_name)

    restored = _poll_until(
        lambda: iam.get_account_summary()["SummaryMap"],
        lambda m: m["Roles"] != after["Roles"] or m["Users"] != after["Users"],
        timeout_s=30.0,
        desc="GetAccountSummary to notice the delete",
    )
    assert restored["Roles"] == base_roles, (
        f"expected Roles to fall back to {base_roles} after delete, got {restored['Roles']}"
    )
    assert restored["Users"] == base_users, (
        f"expected Users to fall back to {base_users} after delete, got {restored['Users']}"
    )

    # The delete is already asserted above via the aggregate count; also confirm it at the
    # entity level, and that a mutation on the now-dead id fails rather than resurrecting it.
    missing_role = f"The role with name {role_name} cannot be found."
    role_code, role_msg = _error(lambda: iam.get_role(RoleName=role_name))
    assert role_code == "NoSuchEntity", f"expected GetRole on the deleted role to be NoSuchEntity, got {role_code}"
    assert role_msg == missing_role, f"GetRole on the deleted role message: {role_msg!r}"
    user_code, user_msg = _error(lambda: iam.get_user(UserName=user_name))
    assert user_code == "NoSuchEntity", f"expected GetUser on the deleted user to be NoSuchEntity, got {user_code}"
    assert user_msg == f"The user with name {user_name} cannot be found.", (
        f"GetUser on the deleted user message: {user_msg!r}"
    )
    role_tag_code, role_tag_msg = _error(
        lambda: iam.tag_role(RoleName=role_name, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert role_tag_code == "NoSuchEntity", (
        f"expected TagRole on the deleted role to be NoSuchEntity, got {role_tag_code}"
    )
    assert role_tag_msg == missing_role, f"TagRole on the deleted role message: {role_tag_msg!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last seen: {last!r}")


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) if it raises ClientError, else raise."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
