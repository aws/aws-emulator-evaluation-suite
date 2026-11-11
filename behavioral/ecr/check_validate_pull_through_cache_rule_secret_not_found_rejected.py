"""validate-pull-through-cache-rule-secret-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-pull-through-cache-rule-secret-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidatePullThroughCacheRule reports isValid=false with UNABLE_TO_ACCESS_SECRET once the
    rule's credential secret is deleted, moves to UPSTREAM_REGISTRY_ACCESS_DENIED after rebinding
    an existing secret, and an ECR Public rule validates."""
    ecr = ctx.client("ecr")
    secretsmanager = ctx.client("secretsmanager")

    broken_prefix = ctx.unique_name("sim2realptcb-")
    secret_name = f"ecr-pullthroughcache/{ctx.unique_name('sim2real-')}"
    secret = secretsmanager.create_secret(
        Name=secret_name, SecretString=json.dumps({"username": "sim2real", "password": "x"})
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: _delete_secret_safe(secretsmanager, secret_arn))

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=broken_prefix,
        upstreamRegistryUrl="registry-1.docker.io",
        upstreamRegistry="docker-hub",
        credentialArn=secret_arn,
    )
    ctx.on_cleanup(lambda: _delete_rule_safe(ecr, broken_prefix))

    secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)

    # A missing secret is reported as a validation failure, not a raised exception.
    broken_result = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=broken_prefix)
    assert broken_result["isValid"] is False, f"expected deleted-secret rule to fail validation: {broken_result!r}"
    broken_failure = broken_result.get("failure") or ""
    assert "UNABLE_TO_ACCESS_SECRET" in broken_failure, (
        f"expected failureCode UNABLE_TO_ACCESS_SECRET for a deleted credential secret, got: {broken_failure!r}"
    )

    # Effect-absent: the rule itself was not deleted or silently repaired.
    still_there = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[broken_prefix])[
        "pullThroughCacheRules"
    ]
    assert still_there[0]["ecrRepositoryPrefix"] == broken_prefix, (
        f"expected the broken rule to still exist after validation, got: {still_there!r}"
    )

    # Rebind to an existing but bogus secret: still invalid, but the failure moves off
    # "secret inaccessible", showing validation re-checks the secret on every call.
    secret2_name = f"ecr-pullthroughcache/{ctx.unique_name('sim2real2-')}"
    secret2 = secretsmanager.create_secret(
        Name=secret2_name,
        SecretString=json.dumps({"username": "sim2real-bogus", "accessToken": "sim2real-bogus-token"}),
    )
    secret2_arn = secret2["ARN"]
    ctx.on_cleanup(lambda: _delete_secret_safe(secretsmanager, secret2_arn))
    update_result = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=broken_prefix, credentialArn=secret2_arn
    )
    assert update_result["credentialArn"] == secret2_arn, (
        f"expected UpdatePullThroughCacheRule to persist the new credentialArn, got: {update_result!r}"
    )

    restored_result = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=broken_prefix)
    assert restored_result["isValid"] is False, (
        f"expected a bogus-but-accessible credential to still fail upstream auth: {restored_result!r}"
    )
    restored_failure = restored_result.get("failure") or ""
    assert "UPSTREAM_REGISTRY_ACCESS_DENIED" in restored_failure, (
        f"expected failureCode to move to UPSTREAM_REGISTRY_ACCESS_DENIED once the secret is "
        f"accessible again, got: {restored_failure!r}"
    )
    assert "UNABLE_TO_ACCESS_SECRET" not in restored_failure, (
        f"expected the secret-inaccessible failureCode to clear once a real secret is bound: {restored_failure!r}"
    )

    # Positive control: ECR Public needs no credentials.
    public_prefix = ctx.unique_name("sim2realptcp-")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=public_prefix,
        upstreamRegistryUrl="public.ecr.aws",
        upstreamRegistry="ecr-public",
    )
    ctx.on_cleanup(lambda: _delete_rule_safe(ecr, public_prefix))

    public_result = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=public_prefix)
    assert public_result["isValid"] is True, f"expected the credential-free ECR Public rule to validate: {public_result!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


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
