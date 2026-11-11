"""update-pull-through-cache-rule-missing-secret-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pull-through-cache-rule-missing-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule naming a nonexistent Secrets Manager secret is refused
    SecretNotFoundException with the exact message and the rule keeps no credentialArn, while an
    update of its customRoleArn is applied and described."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix = "s2r" + uuid.uuid4().hex[:10]
    # a *different* AWS account for the upstream — cross-account ECR-to-ECR pull through
    # cache is the only upstream type that consumes customRoleArn
    upstream_account = "111122223333" if account_id != "111122223333" else "444455556666"

    def _cleanup():
        try:
            ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # a cross-account Amazon ECR private-registry upstream, with an initial custom role
    # ARN attached at creation time (customRoleArn is the auth field this upstream type
    # consumes)
    initial_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-init-{uuid.uuid4().hex[:8]}"
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistryUrl=f"{upstream_account}.dkr.ecr.{ctx.region}.amazonaws.com",
        upstreamRegistry="ecr",
        customRoleArn=initial_role_arn,
    )

    missing_secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:ecr-pullthroughcache/"
        f"sim2real-missing-{uuid.uuid4().hex[:10]}-AbCdEf"
    )

    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, credentialArn=missing_secret_arn
        )
    )
    assert code == "SecretNotFoundException", f"expected SecretNotFoundException, got {code}"
    expected_message = (
        "The ARN of the secret specified in the pull through cache rule was not found. "
        "Update the pull through cache rule with a valid secret ARN and try again."
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # effect absent: the rule's credentialArn was not set by the rejected update
    described = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    rule = described["pullThroughCacheRules"][0]
    assert rule.get("credentialArn") is None, (
        f"expected credentialArn unset after rejected update, got {rule.get('credentialArn')!r}"
    )

    # positive control: updating with this upstream type's applicable auth field (a
    # custom role ARN, for the "ecr" upstream) succeeds
    custom_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-ecr-control-{uuid.uuid4().hex[:8]}"
    update_resp = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, customRoleArn=custom_role_arn
    )
    assert update_resp["customRoleArn"] == custom_role_arn, (
        f"expected customRoleArn {custom_role_arn}, got {update_resp['customRoleArn']!r}"
    )

    described_after = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    after_role_arn = described_after["pullThroughCacheRules"][0]["customRoleArn"]
    assert after_role_arn == custom_role_arn, (
        f"expected persisted customRoleArn {custom_role_arn}, got {after_role_arn!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


