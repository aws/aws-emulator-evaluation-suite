"""create-approval-team-invalid-name-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-approval-team-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApprovalTeam with a Name outside ^[a-zA-Z0-9._-]+$ fails from a non-management account with
    the identical AccessDeniedException a well-formed Name gets, and no team is created: the
    organization gate precedes shape validation.
    """
    sts = ctx.client("sts")
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    account = sts.get_caller_identity()["Account"]

    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy_arn = policies[0]["Arn"] + f"/{policies[0]['DefaultVersion']}"
    approver = {
        "PrimaryIdentityId": uuid.uuid4().hex[:20],
        "PrimaryIdentitySourceArn": (
            f"arn:aws:mpa:us-east-1:{account}:identity-source/{uuid.uuid4().hex}"
        ),
    }

    def _attempt(name):
        return _try_create(
            mpa,
            Name=name,
            Description="sim2real invalid-name-pattern probe",
            ApprovalStrategy={"MofN": {"MinApprovalsRequired": 1}},
            Approvers=[approver],
            Policies=[{"PolicyArn": policy_arn}],
        )

    # a space violates the service's Name pattern, but botocore does not
    # enforce `pattern` client-side (only length), so this reaches the service.
    invalid_name = f"sim2real invalid name {uuid.uuid4().hex}"
    invalid_code, unexpected = _attempt(invalid_name)
    if unexpected is not None:
        ctx.on_cleanup(
            lambda: _best_effort_delete(mpa, unexpected["Arn"], unexpected["VersionId"])
        )
        raise AssertionError(
            f"expected AccessDeniedException for a Name violating the pattern "
            f"from a non-management-account caller, but CreateApprovalTeam "
            f"unexpectedly succeeded: {unexpected}"
        )
    assert invalid_code == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), invalid_code

    valid_name = ctx.unique_name("sim2real-mpa-invalid-name-ctrl-")
    valid_code, unexpected2 = _attempt(valid_name)
    if unexpected2 is not None:
        ctx.on_cleanup(
            lambda: _best_effort_delete(mpa, unexpected2["Arn"], unexpected2["VersionId"])
        )
        raise AssertionError(
            f"expected AccessDeniedException from a non-management-account "
            f"caller, but CreateApprovalTeam unexpectedly succeeded with a "
            f"well-formed Name: {unexpected2}"
        )
    assert valid_code == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), valid_code

    # effect absent: neither the malformed-name nor the well-formed-name
    # attempt created a team
    matching = [
        t for t in _list_all_teams(mpa) if t["Name"] in (invalid_name, valid_name)
    ]
    assert len(matching) == 0


def _try_create(mpa, **kwargs):
    try:
        return None, mpa.create_approval_team(**kwargs)
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message")), None


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
