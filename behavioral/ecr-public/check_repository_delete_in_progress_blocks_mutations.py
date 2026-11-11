"""repository-delete-in-progress-blocks-mutations."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-delete-in-progress-blocks-mutations"
GROUP = "state-machine"
SERVICES = ["ecr-public"]


def _error(fn):
    """Run `fn`, which must fail; return its (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to fail with a ClientError, but it succeeded")


def _ecrpub_client(ctx):
    """An ecr-public client pinned to us-east-1, the only region that serves it."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRepositoryPolicy on a deleted repository fails RepositoryNotFoundException without
    resurrecting it, while the same call succeeds on a live repository.
    """
    ecrpub = _ecrpub_client(ctx)

    deleted_repo = ctx.unique_name("sim2real-ecrpub-deleted-")
    ecrpub.create_repository(
        repositoryName=deleted_repo,
        tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    ecrpub.delete_repository(repositoryName=deleted_repo)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPull",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["ecr-public:GetRepositoryPolicy", "ecr-public:BatchCheckLayerAvailability"],
            }
        ],
    }
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"The repository with name '{deleted_repo}' does not exist in the registry "
        f"with id '{account}'"
    )
    code, message = _error(
        lambda: ecrpub.set_repository_policy(
            repositoryName=deleted_repo, policyText=json.dumps(policy)
        )
    )
    assert code == "RepositoryNotFoundException", (
        f"expected SetRepositoryPolicy on a deleted repository to fail with "
        f"RepositoryNotFoundException, got {code}"
    )
    assert message == not_found, f"SetRepositoryPolicy message: {message!r}"

    code_get, message_get = _error(
        lambda: ecrpub.get_repository_policy(repositoryName=deleted_repo)
    )
    assert code_get == "RepositoryNotFoundException", (
        f"expected GetRepositoryPolicy on a deleted repository to fail with "
        f"RepositoryNotFoundException, got {code_get}"
    )
    assert message_get == not_found, f"GetRepositoryPolicy message: {message_get!r}"
    code_describe, message_describe = _error(
        lambda: ecrpub.describe_repositories(repositoryNames=[deleted_repo])
    )
    assert code_describe == "RepositoryNotFoundException", (
        f"expected DescribeRepositories on a deleted repository to fail with "
        f"RepositoryNotFoundException, got {code_describe}"
    )
    assert message_describe == not_found, (
        f"DescribeRepositories message: {message_describe!r}"
    )

    live_repo = ctx.unique_name("sim2real-ecrpub-live-")
    ecrpub.create_repository(
        repositoryName=live_repo,
        tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ecrpub.delete_repository(repositoryName=live_repo))
    ecrpub.set_repository_policy(repositoryName=live_repo, policyText=json.dumps(policy))
    persisted = ecrpub.get_repository_policy(repositoryName=live_repo)["policyText"]
    persisted_sid = json.loads(persisted)["Statement"][0]["Sid"]
    assert persisted_sid == "AllowPull", (
        f"expected the persisted policy's first statement Sid to be AllowPull, got {persisted_sid}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
