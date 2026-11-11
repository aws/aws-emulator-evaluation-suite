"""update-pull-through-cache-rule-invalid-upstream-rejected."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-pull-through-cache-rule-invalid-upstream-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule with a malformed customRoleArn is rejected with
    InvalidParameterException and the exact message, and the rule is left unchanged."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    secretsmanager = ctx.client("secretsmanager")
    sts.get_caller_identity()["Account"]

    # ECR requires the ecr-pullthroughcache/ prefix on credential secrets.
    secret_name = f"ecr-pullthroughcache/{ctx.unique_name('sim2real-behav-')}"
    secret = secretsmanager.create_secret(
        Name=secret_name, SecretString=json.dumps({"username": "u", "password": "p"})
    )
    well_formed_credential_arn = secret["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_secret(ctx, well_formed_credential_arn))

    prefix = _ecr_prefix(ctx, "upd")
    # Docker Hub supports credentialArn auth (public.ecr.aws does not) and requires a
    # credentialArn at create time.
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="docker-hub",
        upstreamRegistryUrl="registry-1.docker.io",
        credentialArn=well_formed_credential_arn,
    )
    ctx.on_cleanup(lambda: _safe_delete_ptc_rule(ctx, prefix))

    before = _describe_rule(ecr, prefix)
    assert before.get("credentialArn") == well_formed_credential_arn, (
        f"expected credentialArn {well_formed_credential_arn!r} on the freshly created rule, "
        f"got {before.get('credentialArn')!r}"
    )
    assert before.get("customRoleArn") is None, (
        f"expected no customRoleArn on the freshly created rule, got {before.get('customRoleArn')!r}"
    )

    # credentialArn and customRoleArn must be supplied together (customRoleArn alone fails a
    # different check first), so a valid credentialArn isolates the malformed-ARN rejection.
    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix,
            credentialArn=well_formed_credential_arn,
            customRoleArn="not-an-arn",
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed customRoleArn, got {code!r}"
    )
    expected_message = "Invalid role ARN supplied in request."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the malformed value never got persisted against the rule.
    after = _describe_rule(ecr, prefix)
    assert after.get("customRoleArn") is None, (
        f"expected the rejected update to leave customRoleArn unset, got {after.get('customRoleArn')!r}"
    )
    assert after.get("credentialArn") == well_formed_credential_arn, (
        f"expected the rejected update to leave credentialArn at {well_formed_credential_arn!r}, "
        f"got {after.get('credentialArn')!r}"
    )

    # Positive control: the same operation succeeds when given a
    # well-formed credentialArn on its own.
    updated = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, credentialArn=well_formed_credential_arn
    )
    assert updated["ecrRepositoryPrefix"] == prefix, (
        f"expected the update response to echo prefix {prefix!r}, got {updated['ecrRepositoryPrefix']!r}"
    )

    # Independent read-back of the positive-control update.
    final = _describe_rule(ecr, prefix)
    assert final.get("credentialArn") == well_formed_credential_arn, (
        f"expected an independent describe to reflect credentialArn "
        f"{well_formed_credential_arn!r} after the positive control update, "
        f"got {final.get('credentialArn')!r}"
    )
    assert final.get("customRoleArn") is None, (
        f"expected the positive-control update (which supplies no customRoleArn) to leave it "
        f"unset, got {final.get('customRoleArn')!r}"
    )



def _ecr_prefix(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real{tag}")
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"sim2real{tag}{digest}"[:30]


def _describe_rule(ecr, prefix: str) -> dict:
    resp = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    return resp["pullThroughCacheRules"][0]


def _error(fn):
    """Return the (code, message) of the error fn() raises; fail if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _safe_delete_ptc_rule(ctx, prefix: str) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as err:
        if err.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


def _safe_delete_secret(ctx, secret_arn: str) -> None:
    secretsmanager = ctx.client("secretsmanager")
    try:
        secretsmanager.delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
