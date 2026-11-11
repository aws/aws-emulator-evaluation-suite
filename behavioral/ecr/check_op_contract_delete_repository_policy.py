"""op-contract-deleteRepositoryPolicy."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteRepositoryPolicy"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryPolicy returns the removed policy text and clears it; on a repository with
    no policy it raises RepositoryPolicyNotFoundException and no policy materializes."""
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
                "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
            }
        ],
    }
    ecr.set_repository_policy(repositoryName=name, policyText=json.dumps(policy))

    resp = ecr.delete_repository_policy(repositoryName=name)
    assert resp["repositoryName"] == name, (
        f"expected DeleteRepositoryPolicy to echo repositoryName {name!r}, got {resp['repositoryName']!r}"
    )
    assert json.loads(resp["policyText"]) == policy, (
        f"expected the removed policy text to equal what was set {policy!r}, got {resp['policyText']!r}"
    )

    code, code_msg = _error(lambda: ecr.get_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", (
        f"expected an independent GetRepositoryPolicy read to raise RepositoryPolicyNotFoundException "
        f"after the delete, got {code!r}"
    )
    expected_msg = f"Repository policy does not exist for the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Fresh repository that never had a policy set hits the same not-found boundary.
    fresh_repo = _create_repo(ctx)
    fresh_name = fresh_repo["repositoryName"]
    code_fresh, code_fresh_msg = _error(lambda: ecr.delete_repository_policy(repositoryName=fresh_name))
    assert code_fresh == "RepositoryPolicyNotFoundException", (
        f"expected DeleteRepositoryPolicy on a repository that never had a policy to raise "
        f"RepositoryPolicyNotFoundException, got {code_fresh!r}"
    )
    expected_msg = f"Repository policy does not exist for the repository with name '{fresh_name}' in the registry with id '{ctx.account}'"
    assert code_fresh_msg == expected_msg, f"expected message {expected_msg!r}, got {code_fresh_msg!r}"

    code_fresh_read, code_fresh_read_msg = _error(lambda: ecr.get_repository_policy(repositoryName=fresh_name))
    assert code_fresh_read == "RepositoryPolicyNotFoundException", (
        f"expected an independent GetRepositoryPolicy read on {fresh_name!r} to confirm no policy "
        f"materialized, got {code_fresh_read!r}"
    )
    expected_msg = f"Repository policy does not exist for the repository with name '{fresh_name}' in the registry with id '{ctx.account}'"
    assert code_fresh_read_msg == expected_msg, f"expected message {expected_msg!r}, got {code_fresh_read_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
