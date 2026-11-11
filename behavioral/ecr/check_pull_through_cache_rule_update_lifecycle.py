"""pull-through-cache-rule-update-lifecycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-through-cache-rule-update-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Rule created, updated (role), the update persists, and — independently — a rule
    validates successfully right after creation but fails validation with not-found once
    deleted."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix_public = "s2r" + uuid.uuid4().hex[:10]
    prefix_role = "s2r" + uuid.uuid4().hex[:10]
    # a *different* AWS account for the upstream — cross-account ECR-to-ECR pull through
    # cache is the only upstream type that consumes customRoleArn
    upstream_account = "111122223333" if account_id != "111122223333" else "444455556666"

    def _cleanup():
        for prefix in (prefix_public, prefix_role):
            try:
                ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
            except ClientError as e:
                if e.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # --- create -> validate (True) -> delete -> validate (not-found) ---
    # Amazon ECR Public upstream requires no credentials for anonymous pulls, so this
    # rule validates successfully right after creation.
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix_public,
        upstreamRegistryUrl="public.ecr.aws",
        upstreamRegistry="ecr-public",
    )

    validate_resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix_public)
    assert validate_resp["isValid"] is True, validate_resp.get("failure")

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix_public)

    code, message = _error_code(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix_public)
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException after deleting the public-upstream "
        f"rule, got {code!r}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{prefix_public}' does not exist in "
        f"the registry with id '{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- create (with role) -> update (role changes) -> persists ---
    # cross-account ECR-to-ECR is the upstream type that consumes customRoleArn.
    initial_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-ptc-init-{uuid.uuid4().hex[:8]}"
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix_role,
        upstreamRegistryUrl=f"{upstream_account}.dkr.ecr.{ctx.region}.amazonaws.com",
        upstreamRegistry="ecr",
        customRoleArn=initial_role_arn,
    )

    updated_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-ptc-{uuid.uuid4().hex[:8]}"
    update_resp = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix_role, customRoleArn=updated_role_arn
    )
    assert update_resp["customRoleArn"] == updated_role_arn, (
        f"UpdatePullThroughCacheRule response customRoleArn: expected {updated_role_arn!r}, "
        f"got {update_resp.get('customRoleArn')!r}"
    )

    described = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix_role])
    described_role_arn = described["pullThroughCacheRules"][0].get("customRoleArn")
    assert described_role_arn == updated_role_arn, (
        f"DescribePullThroughCacheRules customRoleArn after update: expected "
        f"{updated_role_arn!r}, got {described_role_arn!r}"
    )

    # delete this rule too causes subsequent validation to fail with not-found
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix_role)
    code_role, message_role = _error_code(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix_role)
    )
    assert code_role == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException after deleting the role-bearing "
        f"rule, got {code_role!r}"
    )
    expected_role_message = (
        f"A pull-through cache rule with repository prefix '{prefix_role}' does not exist in "
        f"the registry with id '{account_id}'"
    )
    assert message_role == expected_role_message, (
        f"expected message {expected_role_message!r}, got {message_role!r}"
    )


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)



