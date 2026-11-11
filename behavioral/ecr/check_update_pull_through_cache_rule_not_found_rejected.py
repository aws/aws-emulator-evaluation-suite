"""update-pull-through-cache-rule-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pull-through-cache-rule-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule against an ecrRepositoryPrefix with no registered
    rule raises PullThroughCacheRuleNotFoundException, and succeeds once a rule for
    that prefix has been created."""
    ecr = ctx.client("ecr")
    secretsmanager = ctx.client("secretsmanager")
    prefix = ctx.unique_name("sim2realptc-")

    # credentialArn must match ECR's ARN pattern for the request to pass parameter
    # validation at all (an update with none of credentialArn/customRoleArn set is
    # itself an InvalidParameterException) -- so use a real secret's ARN.
    secret_name = f"ecr-pullthroughcache/{ctx.unique_name('sim2real-')}"
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "sim2real", "password": "x"}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: _delete_secret_safe(secretsmanager, secret_arn))

    # No rule for this prefix exists yet -> update must fail with NotFound, even
    # though the credentialArn itself is well-formed and points at a real secret.
    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, credentialArn=secret_arn
        )
    )
    assert code == "PullThroughCacheRuleNotFoundException", code
    expected_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # Effect-absent: no rule exists for the prefix (confirmed via the same NotFound).
    describe_code, describe_message = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    )
    assert describe_code == "PullThroughCacheRuleNotFoundException", describe_code
    expected_describe_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert describe_message == expected_describe_message, (
        f"expected the exact refusal message {expected_describe_message!r}, got {describe_message!r}"
    )

    # Positive control: create the rule (authenticated docker-hub upstream), then
    # the same update succeeds once the rule exists.
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistryUrl="registry-1.docker.io",
        upstreamRegistry="docker-hub",
        credentialArn=secret_arn,
    )
    ctx.on_cleanup(lambda: _delete_rule_safe(ecr, prefix))

    update_resp = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, credentialArn=secret_arn
    )
    assert update_resp["ecrRepositoryPrefix"] == prefix
    assert update_resp["credentialArn"] == secret_arn

    updated = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    rule = updated["pullThroughCacheRules"][0]
    assert rule["credentialArn"] == secret_arn

    # Delete what we created, then prove it: an independent read reports the same
    # NotFound this check opened with, and a mutation on the now-dead prefix fails too.
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    gone_code, gone_message = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    )
    assert gone_code == "PullThroughCacheRuleNotFoundException", gone_code
    expected_gone_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert gone_message == expected_gone_message, (
        f"expected the exact refusal message {expected_gone_message!r}, got {gone_message!r}"
    )
    post_delete_code, post_delete_message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, credentialArn=secret_arn
        )
    )
    assert post_delete_code == "PullThroughCacheRuleNotFoundException", post_delete_code
    expected_post_delete_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert post_delete_message == expected_post_delete_message, (
        f"expected the exact refusal message {expected_post_delete_message!r}, got {post_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_rule_safe(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


def _delete_secret_safe(secretsmanager, secret_arn: str) -> None:
    try:
        secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



