"""concurrent-create-same-name-exactly-one-wins."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-same-name-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateApprovalTeam calls with the same Name from a non-management account all fail
    with AccessDeniedException and create no team, while GetPolicyVersion on a built-in managed
    policy succeeds: the organization gate holds under concurrency.
    """
    sts = ctx.client("sts")
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    account = sts.get_caller_identity()["Account"]

    # positive control: this account/Region/credentials are otherwise good
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (fetched["PolicyArn"], policy["Arn"])
    policy_arn = policy["Arn"] + f"/{policy['DefaultVersion']}"

    name = ctx.unique_name("sim2real-mpa-race-")

    def attempt(_i):
        approver = {
            "PrimaryIdentityId": uuid.uuid4().hex[:20],
            "PrimaryIdentitySourceArn": (
                f"arn:aws:mpa:us-east-1:{account}:identity-source/{uuid.uuid4().hex}"
            ),
        }
        try:
            resp = mpa.create_approval_team(
                Name=name,
                Description="sim2real concurrent-create-same-name race probe",
                ApprovalStrategy={"MofN": {"MinApprovalsRequired": 1}},
                Approvers=[approver],
                Policies=[{"PolicyArn": policy_arn}],
                Tags={"sim2real-check": "concurrent-create-same-name-exactly-one-wins"},
            )
            return ("ok", resp)
        except ClientError as e:
            return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    successes = [r for kind, r in results if kind == "ok"]
    codes = [r for kind, r in results if kind == "error"]

    if successes:
        ctx.on_cleanup(lambda: _best_effort_delete_all(mpa, successes))
    assert len(successes) == 0, (
        f"expected every concurrent CreateApprovalTeam from a non-management-"
        f"account caller to be denied, but {len(successes)} succeeded: {successes}"
    )
    assert len(codes) == 8, f"expected 8 errors, got {results}"
    assert {code for code, _ in codes} == {"AccessDeniedException"}, codes
    assert {message for _, message in codes} == {MANAGEMENT_ACCOUNT_ONLY}, codes

    # effect absent: no team was created under this name by any concurrent attempt
    matching = [t for t in _list_all_teams(mpa) if t["Name"] == name]
    assert len(matching) == 0, matching


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


def _best_effort_delete_all(mpa, successes):
    for resp in successes:
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
