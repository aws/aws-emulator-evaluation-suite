"""approval-team-fails-validation-for-unknown-approver."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "approval-team-fails-validation-for-unknown-approver"
GROUP = "error-semantics"
SERVICES = ["mpa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource, ListResourcePolicies and GetResourcePolicy refuse a malformed ResourceArn
    with ValidationException "Invalid Resource Arn", while GetPolicyVersion on a built-in managed
    policy succeeds.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    malformed_arn = "not-an-arn-at-all"

    list_tags_code, list_tags_message = _error(
        lambda: mpa.list_tags_for_resource(ResourceArn=malformed_arn)
    )
    assert list_tags_code == "ValidationException", list_tags_code
    assert list_tags_message == "Invalid Resource Arn", list_tags_message

    list_policies_code, list_policies_message = _error(
        lambda: mpa.list_resource_policies(ResourceArn=malformed_arn)
    )
    assert list_policies_code == "ValidationException", list_policies_code
    assert list_policies_message == "Invalid Resource Arn", list_policies_message

    get_policy_code, get_policy_message = _error(
        lambda: mpa.get_resource_policy(
            ResourceArn=malformed_arn,
            PolicyType="AWS_MANAGED",
            PolicyName="sim2real-probe",
        )
    )
    assert get_policy_code == "ValidationException", get_policy_code
    assert get_policy_message == "Invalid Resource Arn", get_policy_message

    # positive control: this account/Region/credentials are otherwise good
    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    fetched = mpa.get_policy_version(
        PolicyVersionArn=policy["Arn"] + f"/{policy['DefaultVersion']}"
    )["PolicyVersion"]
    assert fetched["PolicyArn"] == policy["Arn"], (
        f"expected {policy['Arn']}, got {fetched['PolicyArn']}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
