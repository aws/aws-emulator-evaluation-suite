"""get-policy-version-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-policy-version-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["mpa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicyVersion rejects a PolicyVersionArn that doesn't match the AWS
    managed policy ARN pattern with ValidationException, while a real policy
    version ARN taken from ListPolicies resolves successfully."""
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")

    err = _error(
        lambda: mpa.get_policy_version(
            PolicyVersionArn="arn:aws:iam::123456789012:policy/foo"
        )
    )
    assert err == ("ValidationException", "Invalid Resource Arn"), err

    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]
    version_arn = policy["Arn"] + f"/{policy['DefaultVersion']}"
    fetched = mpa.get_policy_version(PolicyVersionArn=version_arn)["PolicyVersion"]
    assert fetched["Arn"] == version_arn, f"expected Arn {version_arn!r}, got {fetched['Arn']!r}"


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
