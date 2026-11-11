"""delete-repository-policy-on-nonexistent-repository-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-repository-policy-on-nonexistent-repository-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """An ecr-public client pinned to us-east-1, the only region that serves it."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryPolicy on a nonexistent repository fails RepositoryNotFoundException and
    does not create it; a real repository's policy deletes successfully."""
    ecrp = _ecrpub_client(ctx)

    missing_repo = ctx.unique_name("sim2real-ghost-repo-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"The repository with name '{missing_repo}' does not exist in the registry "
        f"with id '{account}'"
    )

    code, message = _error(lambda: ecrp.delete_repository_policy(repositoryName=missing_repo))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == not_found, f"DeleteRepositoryPolicy message: {message!r}"

    describe_code, describe_message = _error(
        lambda: ecrp.describe_repositories(repositoryNames=[missing_repo])
    )
    assert describe_code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException, got {describe_code}"
    )
    assert describe_message == not_found, f"DescribeRepositories message: {describe_message!r}"

    repo_name = ctx.unique_name("sim2real-delpolicy-")
    ecrp.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    policy_text = _basic_policy_document(repo_name)
    ecrp.set_repository_policy(repositoryName=repo_name, policyText=policy_text)

    ecrp.delete_repository_policy(repositoryName=repo_name)

    after_delete_code, after_delete_message = _error(
        lambda: ecrp.get_repository_policy(repositoryName=repo_name)
    )
    assert after_delete_code == "RepositoryPolicyNotFoundException", (
        f"expected RepositoryPolicyNotFoundException, got {after_delete_code}"
    )
    assert after_delete_message == (
        f"Repository policy does not exist for the repository with name '{repo_name}' in the "
        f"registry with id '{account}'"
    ), f"GetRepositoryPolicy message: {after_delete_message!r}"


def _error(fn) -> Any:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _basic_policy_document(repo_name: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPull",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["ecr-public:BatchCheckLayerAvailability"],
                }
            ],
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
