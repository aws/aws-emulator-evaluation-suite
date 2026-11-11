"""update-pull-through-cache-rule-secret-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pull-through-cache-rule-secret-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule with a well-formed but nonexistent Secrets Manager ARN fails with
    SecretNotFoundException and leaves credentialArn unchanged; updating with a real secret
    succeeds."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    secretsmanager = ctx.client("secretsmanager")
    account_id = sts.get_caller_identity()["Account"]

    prefix = _ptc_prefix()
    secret_name = f"ecr-pullthroughcache/{ctx.unique_name('sim2real-ptc-secret')}"
    secret = secretsmanager.create_secret(Name=secret_name, SecretString="{}")
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="docker-hub",
        upstreamRegistryUrl="registry-1.docker.io",
        credentialArn=secret_arn,
    )
    ctx.on_cleanup(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix))

    missing_secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:"
        f"ecr-pullthroughcache/sim2real-missing-secret-{uuid.uuid4().hex[:12]}"
    )
    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, credentialArn=missing_secret_arn
        )
    )
    assert code == "SecretNotFoundException", code
    expected_message = (
        "The ARN of the secret specified in the pull through cache rule was not found. "
        "Update the pull through cache rule with a valid secret ARN and try again."
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    rules = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    got_after_reject = rules[0].get("credentialArn")
    assert got_after_reject == secret_arn, (secret_arn, got_after_reject)

    secret_name2 = f"ecr-pullthroughcache/{ctx.unique_name('sim2real-ptc-secret2')}"
    secret2 = secretsmanager.create_secret(Name=secret_name2, SecretString="{}")
    secret_arn2 = secret2["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn2, ForceDeleteWithoutRecovery=True)
    )
    resp = ecr.update_pull_through_cache_rule(ecrRepositoryPrefix=prefix, credentialArn=secret_arn2)
    assert resp["credentialArn"] == secret_arn2, (secret_arn2, resp.get("credentialArn"))

    described = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    got_final = described[0].get("credentialArn")
    assert got_final == secret_arn2, (secret_arn2, got_final)





def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ptc_prefix():
    return "s2r" + uuid.uuid4().hex[:12]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
