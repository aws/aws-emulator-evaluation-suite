"""delete-repository-policy-not-set-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-policy-not-set-error"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryPolicy on a repository with no policy attached raises
    RepositoryPolicyNotFoundException instead of silently succeeding as a no-op."""
    ecrpublic = _ecrpublic(ctx)
    name = ctx.unique_name("sim2real-behav-ecrpub-pol-")
    ecrpublic.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=name, force=True))
    account = ctx.client("sts").get_caller_identity()["Account"]
    no_policy = (
        f"Repository policy does not exist for the repository with name '{name}' in the registry "
        f"with id '{account}'"
    )

    # No policy has ever been set on this brand-new repository.
    code, message = _error(lambda: ecrpublic.delete_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", (
        f"expected RepositoryPolicyNotFoundException deleting a policy that was never set, got {code}"
    )
    assert message == no_policy, f"DeleteRepositoryPolicy message: {message!r}"

    # Effect absent: the repository still has no policy afterwards -- the failed delete did
    # not somehow create, corrupt, or otherwise change the (nonexistent) policy state.
    code, message = _error(lambda: ecrpublic.get_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", (
        f"expected the still-absent policy to read as RepositoryPolicyNotFoundException, got {code}"
    )
    assert message == no_policy, f"GetRepositoryPolicy message: {message!r}"

    # Positive control: once a policy genuinely exists, DeleteRepositoryPolicy succeeds and
    # actually removes it.
    policy = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowPull","Effect":"Allow",'
        '"Principal":"*","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]}]}'
    )
    ecrpublic.set_repository_policy(repositoryName=name, policyText=policy)
    deleted = ecrpublic.delete_repository_policy(repositoryName=name)
    assert deleted["repositoryName"] == name, (
        f"expected DeleteRepositoryPolicy's response to name {name!r}, got {deleted.get('repositoryName')!r}"
    )

    code, message = _error(lambda: ecrpublic.get_repository_policy(repositoryName=name))
    assert code == "RepositoryPolicyNotFoundException", (
        f"expected the just-deleted policy to read as RepositoryPolicyNotFoundException, got {code}"
    )
    assert message == no_policy, f"GetRepositoryPolicy message: {message!r}"


def _error(fn):
    """Call fn() and return the AWS (Error.Code, Error.Message). A call that SUCCEEDS raises: an
    emulator accepting input real AWS rejects is the strongest signal available here."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so the client is pinned
    there through `ctx.client(..., region=)`."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
