"""create-approval-team-missing-permission-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-approval-team-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fully privileged caller outside an organization's management account gets AccessDeniedException
    from CreateApprovalTeam and creates no team: the organization gate does not depend on IAM grants.
    """
    sts = ctx.client("sts")
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    account = sts.get_caller_identity()["Account"]

    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy_arn = policies[0]["Arn"] + f"/{policies[0]['DefaultVersion']}"
    name = ctx.unique_name("sim2real-mpa-denied-")
    approver = {
        "PrimaryIdentityId": uuid.uuid4().hex[:20],
        "PrimaryIdentitySourceArn": (
            f"arn:aws:mpa:us-east-1:{account}:identity-source/{uuid.uuid4().hex}"
        ),
    }

    code, message, unexpected_response = _try_create(
        mpa,
        Name=name,
        Description="sim2real denied team",
        ApprovalStrategy={"MofN": {"MinApprovalsRequired": 1}},
        Approvers=[approver],
        Policies=[{"PolicyArn": policy_arn}],
    )
    if unexpected_response is not None:
        ctx.on_cleanup(
            lambda: _best_effort_delete(
                mpa, unexpected_response["Arn"], unexpected_response["VersionId"]
            )
        )
        raise AssertionError(
            f"expected AccessDeniedException from a non-management-account caller, "
            f"but CreateApprovalTeam unexpectedly succeeded: {unexpected_response}"
        )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    # The code alone would also match "caller lacks mpa:CreateApprovalTeam" -- pin the
    # message to the management-account precondition specifically.
    assert message == MANAGEMENT_ACCOUNT_ONLY, (
        f"AccessDeniedException message does not name the management-account "
        f"precondition, got: {message!r}"
    )

    # effect absent: no team was created under this name
    matching = [t for t in _list_all_teams(mpa) if t["Name"] == name]
    assert len(matching) == 0, f"expected no team named {name!r}, found: {matching}"


def _try_create(mpa, **kwargs):
    try:
        return None, None, mpa.create_approval_team(**kwargs)
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), None


def _list_all_teams(mpa):
    teams = []
    token = None
    while True:
        page_kwargs = {"MaxResults": 20}
        if token:
            page_kwargs["NextToken"] = token
        resp = mpa.list_approval_teams(**page_kwargs)
        teams.extend(resp.get("ApprovalTeams", []))
        token = resp.get("NextToken")
        if not token:
            break
    return teams


def _best_effort_delete(mpa, arn, version_id):
    try:
        mpa.delete_inactive_approval_team_version(Arn=arn, VersionId=version_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
