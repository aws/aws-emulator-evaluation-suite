"""e2e-pull-through-cache-validate-update-cycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-pull-through-cache-validate-update-cycle"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdatePullThroughCacheRule swaps the credential secret, Describe reports the new
    credentialArn and Validate resolves it: deleting the original secret does not turn the
    failure into a secret-access one."""
    ecr = ctx.client("ecr")
    secretsmanager = ctx.client("secretsmanager")

    # ECR pull-through cache secrets need 'username' and 'accessToken' keys; any other shape
    # fails validation with UNABLE_TO_PARSE_SECRET before reaching upstream authentication.
    def _make_secret(tag: str, token: str) -> dict:
        name = ctx.unique_name(f"ecr-pullthroughcache/sim2real-ptc-{tag}-")
        secret = secretsmanager.create_secret(
            Name=name,
            SecretString=json.dumps({"username": "sim2real-bogus-user", "accessToken": token}),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        return secret

    def _delete_secret(arn: str) -> None:
        try:
            secretsmanager.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        except secretsmanager.exceptions.ResourceNotFoundException:
            pass

    # A pull-through cache rule created WITH a credentialArn is "authenticated";
    # only an authenticated rule's credentials can later be changed via Update
    # (an unauthenticated rule's Update for credentialArn is rejected outright).
    secret1 = _make_secret("a", "sim2real-bogus-token-000")
    ctx.on_cleanup(lambda: _delete_secret(secret1["ARN"]))

    prefix = ctx.unique_name("sim2real-ptc-")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="docker-hub",
        upstreamRegistryUrl="registry-1.docker.io",
        credentialArn=secret1["ARN"],
    )
    ctx.on_cleanup(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix))

    rules_before = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])["pullThroughCacheRules"]
    assert len(rules_before) == 1
    assert rules_before[0]["credentialArn"] == secret1["ARN"]

    # On an account's first pull-through cache rule, ECR's service-linked role is still being
    # provisioned and briefly reports UNABLE_TO_ACCESS_SECRET; retry through that transient.
    before = _retry_while_slr_provisioning(ecr, prefix)
    assert before["isValid"] is False, f"expected bogus-credential rule to fail validation: {before!r}"
    before_failure = _parse_failure(before)
    assert before_failure["failureCode"] not in _SECRET_UNREACHABLE_CODES, (
        f"expected an upstream authentication failure, not a secret-access failure: {before_failure!r}"
    )

    secret2 = _make_secret("b", "sim2real-bogus-token-111")
    secret2_arn = secret2["ARN"]
    ctx.on_cleanup(lambda: _delete_secret(secret2_arn))
    ecr.update_pull_through_cache_rule(ecrRepositoryPrefix=prefix, credentialArn=secret2_arn)

    rules_after = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])["pullThroughCacheRules"]
    assert len(rules_after) == 1
    assert rules_after[0]["credentialArn"] == secret2_arn, "UpdatePullThroughCacheRule did not persist credentialArn"
    assert rules_after[0]["credentialArn"] != secret1["ARN"]

    # If Validate still resolved the old credentialArn, deleting it would surface as a
    # secret-unreachable failure rather than an authentication failure.
    _delete_secret(secret1["ARN"])

    after = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    assert after["isValid"] is False, f"expected still-bogus-credential rule to fail validation: {after!r}"
    after_failure = _parse_failure(after)
    assert after_failure["failureCode"] not in _SECRET_UNREACHABLE_CODES, (
        "ValidatePullThroughCacheRule failed as though it were still resolving the deleted "
        f"original credentialArn instead of the updated one: {after_failure!r}"
    )


_SECRET_UNREACHABLE_CODES = frozenset({"UNABLE_TO_ACCESS_SECRET", "UNABLE_TO_PARSE_SECRET"})


def _retry_while_slr_provisioning(ecr, prefix: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout_s
    resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    while _failure_code(resp) == "UNABLE_TO_ACCESS_SECRET":
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"ECR still could not access the credential secret after {timeout_s}s "
                f"(service-linked role never finished provisioning?): {resp!r}"
            )
        time.sleep(interval_s)
        resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    return resp


def _failure_code(resp: dict) -> str | None:
    raw = resp.get("failure")
    if not raw:
        return None
    try:
        return json.loads(raw).get("failureCode")
    except (TypeError, ValueError):
        return None


def _parse_failure(resp: dict) -> dict:
    raw = resp.get("failure")
    assert raw, f"expected a failure reason on an invalid rule: {resp!r}"
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise AssertionError(f"failure was not the expected JSON shape: {raw!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
