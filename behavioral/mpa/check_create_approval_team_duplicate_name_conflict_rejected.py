"""create-approval-team-duplicate-name-conflict-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-approval-team-duplicate-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two CreateApprovalTeam calls with the identical Name from a non-management account both fail with
    AccessDeniedException, never ConflictException, and create no team, while GetPolicyVersion on a
    built-in managed policy succeeds.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # positive control: this account/Region/credentials are otherwise good
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (fetched["PolicyArn"], policy["Arn"])

    name = ctx.unique_name("sim2real-mpa-dupname-")
    create_kwargs = dict(
        Name=name,
        Description="sim2real duplicate-name probe",
        ApprovalStrategy={"MofN": {"MinApprovalsRequired": 1}},
        Approvers=[
            {
                "PrimaryIdentityId": uuid.uuid4().hex[:20],
                "PrimaryIdentitySourceArn": (
                    f"arn:aws:mpa:us-east-1:{account}:identity-source/{uuid.uuid4().hex}"
                ),
            }
        ],
        Policies=[{"PolicyArn": policy["Arn"] + f"/{policy['DefaultVersion']}"}],
    )

    first_code, first_response = _try_create(mpa, **create_kwargs)
    if first_response is not None:
        ctx.on_cleanup(
            lambda: _best_effort_delete(
                mpa, first_response["Arn"], first_response["VersionId"]
            )
        )
        raise AssertionError(
            f"expected AccessDeniedException on first CreateApprovalTeam call, "
            f"but it unexpectedly succeeded: {first_response}"
        )
    assert first_code == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), first_code

    # duplicate-name probe: repeat the IDENTICAL call. If Name-uniqueness were
    # ever evaluated for this caller, the second call would escalate to
    # ConflictException; the org-membership gate must instead deny it exactly
    # as it denied the first, proving the gate never leaks whether `name` is
    # already taken.
    second_code, second_response = _try_create(mpa, **create_kwargs)
    if second_response is not None:
        ctx.on_cleanup(
            lambda: _best_effort_delete(
                mpa, second_response["Arn"], second_response["VersionId"]
            )
        )
        raise AssertionError(
            f"expected AccessDeniedException on the repeated CreateApprovalTeam "
            f"call with the identical Name, but it unexpectedly succeeded: "
            f"{second_response}"
        )
    assert second_code == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), second_code

    # effect absent: no team was created under this name by either attempt
    matching = [t for t in _list_all_teams(mpa) if t["Name"] == name]
    assert len(matching) == 0, matching


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

