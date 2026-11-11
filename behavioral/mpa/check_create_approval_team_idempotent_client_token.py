"""create-approval-team-idempotent-client-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-approval-team-idempotent-client-token"
GROUP = "error-semantics"
SERVICES = ["mpa"]
NOT_FOUND = "The requested resource does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicyVersions on a well-formed but nonexistent PolicyArn fails with ResourceNotFoundException,
    while on a built-in managed policy it succeeds and flags as IsDefault the version ListPolicies
    reports.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")

    policies = mpa.list_policies(MaxResults=1)["Policies"]
    assert policies, "account has no MPA managed policies"
    policy = policies[0]

    # build a nonexistent PolicyArn with the same shape as a real one so this
    # exercises resource-existence, not ARN-pattern validation
    bogus_policy_arn = policy["Arn"].rsplit("/", 1)[0] + "/sim2real-nonexistent-policy"
    err = _error(lambda: mpa.list_policy_versions(PolicyArn=bogus_policy_arn))
    assert err == ("ResourceNotFoundException", NOT_FOUND), err

    versions = mpa.list_policy_versions(PolicyArn=policy["Arn"])["PolicyVersions"]
    assert versions, f"no versions returned for real policy {policy['Arn']}"
    default_version = next(v for v in versions if v["VersionId"] == policy["DefaultVersion"])
    assert default_version["IsDefault"] is True, (
        f"expected IsDefault=True for {policy['DefaultVersion']}, got {default_version['IsDefault']}"
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

