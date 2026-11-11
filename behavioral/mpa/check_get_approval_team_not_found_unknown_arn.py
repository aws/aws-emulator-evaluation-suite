"""get-approval-team-not-found-unknown-arn."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-approval-team-not-found-unknown-arn"
GROUP = "error-semantics"
SERVICES = ["mpa"]
NOT_FOUND = "The requested resource does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetApprovalTeam on a well-formed but nonexistent team ARN fails with ResourceNotFoundException,
    while ListPolicies and GetPolicyVersion on the built-in catalog succeed.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:mpa:us-east-1:{account}:approval-team/"
        f"sim2real-nonexistent-{uuid.uuid4().hex}"
    )

    err = _error(lambda: mpa.get_approval_team(Arn=bogus_arn))
    assert err == ("ResourceNotFoundException", NOT_FOUND), (
        f"expected ResourceNotFoundException for a nonexistent Arn, got {err!r}"
    )

    # positive control: this account/Region/credentials are otherwise good
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (
        f"expected GetPolicyVersion to resolve {policy['Arn']!r}, got {fetched['PolicyArn']!r}"
    )


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
