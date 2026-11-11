"""pull-through-cache-rule-custom-role-arn-persists."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pull-through-cache-rule-custom-role-arn-persists"
GROUP = "representation"
SERVICES = ["ecr"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An updated customRoleArn persists exactly on a cross-account ECR upstream rule, the upstream
    repository prefix survives the update, and after deletion a read and an update both fail
    with the specific not-found error."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix = "s2r" + uuid.uuid4().hex[:10]
    upstream_prefix = "library"
    # a *different* AWS account for the upstream — cross-account ECR-to-ECR pull through
    # cache is the only upstream type that consumes customRoleArn
    upstream_account = "111122223333" if account_id != "111122223333" else "444455556666"
    upstream_region = ctx.region

    def _cleanup():
        try:
            ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    initial_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-role-init-{uuid.uuid4().hex[:8]}"
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistryUrl=f"{upstream_account}.dkr.ecr.{upstream_region}.amazonaws.com",
        upstreamRegistry="ecr",
        upstreamRepositoryPrefix=upstream_prefix,
        customRoleArn=initial_role_arn,
    )

    # customRoleArn must be a role in *this* (the configuring) account
    custom_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-role-{uuid.uuid4().hex[:8]}"
    update_resp = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, customRoleArn=custom_role_arn
    )
    assert update_resp["customRoleArn"] == custom_role_arn, (
        f"expected updated customRoleArn {custom_role_arn!r}, "
        f"got {update_resp.get('customRoleArn')!r}"
    )
    assert update_resp["upstreamRepositoryPrefix"] == upstream_prefix, (
        f"unrelated field upstreamRepositoryPrefix changed on update: expected "
        f"{upstream_prefix!r}, got {update_resp.get('upstreamRepositoryPrefix')!r}"
    )

    describe_resp = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    rule = describe_resp["pullThroughCacheRules"][0]
    assert rule["customRoleArn"] == custom_role_arn, (
        f"describe did not reflect the updated customRoleArn: expected {custom_role_arn!r}, "
        f"got {rule.get('customRoleArn')!r}"
    )
    assert rule["upstreamRepositoryPrefix"] == upstream_prefix, (
        f"describe did not preserve upstreamRepositoryPrefix across the update: expected "
        f"{upstream_prefix!r}, got {rule.get('upstreamRepositoryPrefix')!r}"
    )
    assert rule["ecrRepositoryPrefix"] == prefix, (
        f"describe returned a rule for the wrong prefix: expected {prefix!r}, "
        f"got {rule.get('ecrRepositoryPrefix')!r}"
    )

    # the rule is now gone: an independent read and a further mutation on the dead id both
    # fail with the specific not-found error, not a silent success against an absent target
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)

    describe_error = _client_error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    )
    assert describe_error.get("Code") == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException describing a deleted rule, "
        f"got {describe_error!r}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist in the "
        f"registry with id '{account_id}'"
    )
    assert describe_error.get("Message") == expected_message, (
        f"expected message {expected_message!r} describing a deleted rule, got {describe_error!r}"
    )

    update_error = _client_error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, customRoleArn=custom_role_arn
        )
    )
    assert update_error.get("Code") == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException updating a deleted rule, "
        f"got {update_error!r}"
    )
    assert update_error.get("Message") == expected_message, (
        f"expected message {expected_message!r} updating a deleted rule, got {update_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

