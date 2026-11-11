"""tag-resource-exceeds-limit-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["mpa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with 51 tags on a well-formed but nonexistent approval team ARN fails with
    ResourceNotFoundException rather than TooManyTagsException or a success: existence is checked
    before the tag quota.
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

    too_many = {f"sim2real-tag-{i}": "v" for i in range(51)}
    # the tag-family not-found message is the ResourceArn itself
    not_found = ("ResourceNotFoundException", bogus_team_arn)
    err = _error(lambda: mpa.tag_resource(ResourceArn=bogus_team_arn, Tags=too_many))
    assert err == not_found, err

    # a single, in-quota tag against the same bogus ARN hits the identical
    # not-found path -- the outcome doesn't depend on how many tags were sent
    within_quota_err = _error(
        lambda: mpa.tag_resource(ResourceArn=bogus_team_arn, Tags={"sim2real-ok": "v"})
    )
    assert within_quota_err == not_found, within_quota_err

    # positive control: this account/Region/credentials are otherwise healthy
    # for MPA -- without this, "rejects a nonexistent ARN" is indistinguishable
    # from "TagResource never works here"
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (policy["Arn"], fetched["PolicyArn"])


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
