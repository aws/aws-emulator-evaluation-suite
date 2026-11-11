"""min-approvals-exceeds-approver-count-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "min-approvals-exceeds-approver-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApprovalTeam with MinApprovalsRequired 3 over 2 approvers, and with it equal to the approver
    count, both fail from a non-management account with the identical AccessDeniedException and create
    no team: the organization gate precedes the count check.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # positive control: this account/Region/credentials are otherwise good, and this
    # is also the real policy every create attempt below references
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (fetched["PolicyArn"], policy["Arn"])
    policy_version_arn = policy["Arn"] + f"/{policy['DefaultVersion']}"

    def _fabricated_approvers(n):
        return [
            {
                "PrimaryIdentityId": f"sim2real-nonexistent-user-{uuid.uuid4().hex}",
                "PrimaryIdentitySourceArn": (
                    f"arn:aws:mpa:us-east-1:{account}:identity-source/"
                    f"{uuid.uuid4()}"
                ),
            }
            for _ in range(n)
        ]

    def _try_create(min_approvals_required, approvers, name):
        try:
            resp = mpa.create_approval_team(
                Name=name,
                Description="sim2real min-approvals-vs-approver-count probe",
                ApprovalStrategy={
                    "MofN": {"MinApprovalsRequired": min_approvals_required}
                },
                Approvers=approvers,
                Policies=[{"PolicyArn": policy_version_arn}],
            )
            return None, None, resp
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", ""), None

    over_name = ctx.unique_name("sim2realmpaover")
    over_code, over_message, over_resp = _try_create(3, _fabricated_approvers(2), over_name)
    if over_resp is not None:
        ctx.on_cleanup(lambda: _best_effort_delete(mpa, over_resp))
        raise AssertionError(
            "expected AccessDeniedException (org management-account gate) for a "
            "MinApprovalsRequired (3) / Approvers count (2) mismatch from a "
            f"non-management-account caller, but CreateApprovalTeam unexpectedly "
            f"succeeded: {over_resp}"
        )
    assert over_code == "AccessDeniedException", (over_code, over_message)
    assert over_message == MANAGEMENT_ACCOUNT_ONLY, over_message

    # same fabricated approvers; only MinApprovalsRequired changes to equal the
    # approver count, so the input is now valid on its own terms. If the earlier
    # AccessDeniedException were actually about the count mismatch, this call would
    # get a different error (or succeed). It gets the identical error, proving the
    # organization gate is checked unconditionally, before MinApprovalsRequired vs
    # Approvers is ever evaluated.
    equal_name = ctx.unique_name("sim2realmpaequal")
    equal_code, equal_message, equal_resp = _try_create(2, _fabricated_approvers(2), equal_name)
    if equal_resp is not None:
        ctx.on_cleanup(lambda: _best_effort_delete(mpa, equal_resp))
        raise AssertionError(
            "expected the identical AccessDeniedException once MinApprovalsRequired "
            f"equals the approver count, but CreateApprovalTeam unexpectedly "
            f"succeeded: {equal_resp}"
        )
    assert equal_code == "AccessDeniedException", (equal_code, equal_message)
    assert equal_message == over_message, (
        "expected the identical organization-gate message regardless of "
        f"MinApprovalsRequired vs Approvers count: {over_message!r} != {equal_message!r}"
    )

    # effect-absent: neither attempt created a team visible at the destination
    names_seen = {
        t["Name"]
        for page in mpa.get_paginator("list_approval_teams").paginate()
        for t in page["ApprovalTeams"]
    }
    assert over_name not in names_seen and equal_name not in names_seen, (
        over_name,
        equal_name,
        names_seen,
    )


def _best_effort_delete(mpa, resp):
    try:
        mpa.delete_inactive_approval_team_version(
            Arn=resp["Arn"], VersionId=resp["VersionId"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
