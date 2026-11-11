"""delete-inactive-approval-team-version-nonexistent-is-noop."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inactive-approval-team-version-nonexistent-is-noop"
GROUP = "state"
SERVICES = ["mpa"]
NOT_FOUND = "The requested resource does not exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInactiveApprovalTeamVersion on a well-formed but nonexistent team succeeds as a no-op, while
    GetApprovalTeam on the same ARN fails with ResourceNotFoundException and GetPolicyVersion on a
    built-in managed policy succeeds.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    bogus_team_arn = (
        f"arn:aws:mpa:us-east-1:{account}:approval-team/"
        f"sim2real-nonexistent-{uuid.uuid4().hex}"
    )

    # a no-op success: any ClientError propagates and fails the check
    mpa.delete_inactive_approval_team_version(Arn=bogus_team_arn, VersionId="1")

    # contrast: a plain lookup against the very same bogus Arn is NOT forgiving
    get_err = _error(lambda: mpa.get_approval_team(Arn=bogus_team_arn))
    assert get_err == ("ResourceNotFoundException", NOT_FOUND), get_err

    # positive control: this account/Region/credentials are otherwise good, so the
    # not-found result above is specific to the bogus Arn, not a broader outage
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

