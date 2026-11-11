"""op-contract-getRepositoryPolicy."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getRepositoryPolicy"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRepositoryPolicy returns exactly the policyText set via SetRepositoryPolicy;
    calling it on a repository with no resource policy set raises RepositoryPolicyNotFoundException."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPull",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:BatchGetImage",
            }
        ],
    }
    ecr.set_repository_policy(repositoryName=name, policyText=json.dumps(policy))

    resp = ecr.get_repository_policy(repositoryName=name)
    assert resp["repositoryName"] == name, f"expected repositoryName {name!r}, got {resp['repositoryName']!r}"
    got_policy = json.loads(resp["policyText"])
    assert got_policy == policy, f"expected policy {policy!r}, got {got_policy!r}"

    fresh_repo = _create_repo(ctx)
    code, message = _error(lambda: ecr.get_repository_policy(repositoryName=fresh_repo["repositoryName"]))
    assert code == "RepositoryPolicyNotFoundException", (
        f"expected RepositoryPolicyNotFoundException on a repository with no policy, got {code!r}"
    )
    assert message == (
        f"Repository policy does not exist for the repository with name '{fresh_repo['repositoryName']}' in the registry with id '{ctx.account}'"
    ), message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    repo_tags = kwargs.pop("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, tags=repo_tags, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
