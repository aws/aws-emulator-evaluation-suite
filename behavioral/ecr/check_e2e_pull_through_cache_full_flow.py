"""e2e-pull-through-cache-full-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-pull-through-cache-full-flow"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pull-through cache rule for ECR Public validates and serves an upstream image; adding a
    customRoleArn is rejected and not stored; after deletion, validation fails with not-found."""
    ecr = ctx.client("ecr")
    prefix = _ptc_prefix(ctx)

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistryUrl="public.ecr.aws",
        upstreamRegistry="ecr-public",
    )
    ctx.on_cleanup(lambda: _delete_ptc_rule(ecr, prefix))

    validation = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    assert validation["isValid"] is True, f"a freshly created rule must validate: {validation!r}"

    cached_repo_name = f"{prefix}/docker/library/hello-world"
    ctx.on_cleanup(lambda: _delete_repo_if_exists(ecr, cached_repo_name))
    # The first pull through a new rule can fail transiently while ECR fetches from upstream.
    pulled = _pull_with_retry(ecr, cached_repo_name, "latest")
    assert len(pulled["images"]) == 1, f"expected exactly one image for tag latest: {pulled!r}"
    assert pulled["images"][0]["imageId"]["imageTag"] == "latest", (
        f"expected imageTag 'latest', got {pulled['images'][0]['imageId']!r}"
    )
    assert pulled["images"][0]["imageManifest"], (
        f"expected a non-empty cached manifest, got {pulled['images'][0]['imageManifest']!r}"
    )

    # The ECR Public upstream is unauthenticated, so a custom IAM role does not apply to it.
    role_arn = _create_pull_through_role(ctx)
    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(ecrRepositoryPrefix=prefix, customRoleArn=role_arn)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a customRoleArn on an unauthenticated upstream, "
        f"got {code!r}"
    )
    expected = "Invalid input: Please create an authenticated pull through cache rule to update the credentials"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    described = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    rule = described["pullThroughCacheRules"][0]
    assert not rule.get("customRoleArn"), (
        f"the rejected update must not have stored customRoleArn: {rule!r}"
    )

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)

    code, message = _error(lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix))
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException after delete, got {code!r}"
    )
    expected = f"A pull-through cache rule with repository prefix '{prefix}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


import json
import time


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _pull_with_retry(ecr, repo_name, tag, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
            if resp["images"] and not resp["failures"]:
                return resp
            last = resp["failures"]
        except ClientError as exc:
            last = exc
        time.sleep(interval_s)
    raise AssertionError(f"pull-through-cache image never became available: {last!r}")



def _ptc_prefix(ctx):
    raw = ctx.unique_name("sim2realptc-").lower().replace("_", "-")
    raw = raw[:28]
    while raw and raw[-1] in "-_.":
        raw = raw[:-1]
    return raw


def _delete_ptc_rule(ecr, prefix):
    from botocore.exceptions import ClientError

    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


def _delete_repo_if_exists(ecr, repo_name):
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _create_pull_through_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecr-ptc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecr.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
