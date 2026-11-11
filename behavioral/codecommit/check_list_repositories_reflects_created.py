"""list-repositories-reflects-created."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-repositories-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRepositories includes a just-created repository and drops it after delete, when GetRepository
    and a mutation raise RepositoryDoesNotExistException."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(repositoryName=ctx.unique_name("sim2real-behav-repo-"))["repositoryMetadata"]
    name = meta["repositoryName"]
    ctx.on_cleanup(lambda n=name: cc.delete_repository(repositoryName=n))

    def _names():
        names = set()
        paginator = cc.get_paginator("list_repositories")
        for page in paginator.paginate():
            for r in page.get("repositories", []):
                names.add(r["repositoryName"])
        return names

    def _wait_until(predicate, reason):
        deadline = time.monotonic() + 30
        while True:
            if predicate():
                return
            if time.monotonic() >= deadline:
                raise AssertionError(reason)
            time.sleep(2)

    _wait_until(lambda: name in _names(), f"{name} did not appear in ListRepositories within 30s")

    cc.delete_repository(repositoryName=name)

    _wait_until(lambda: name not in _names(), f"{name} still listed by ListRepositories 30s after delete")

    try:
        cc.get_repository(repositoryName=name)
        raise AssertionError(f"GetRepository on deleted {name} unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "RepositoryDoesNotExistException", f"expected RepositoryDoesNotExistException, got {code}"
        message = e.response["Error"].get("Message")
        assert message == f"{name} for {ctx.account}", message

    try:
        cc.update_repository_description(repositoryName=name, repositoryDescription="post-delete")
        raise AssertionError(f"UpdateRepositoryDescription on deleted {name} unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "RepositoryDoesNotExistException", f"expected RepositoryDoesNotExistException, got {code}"
        message = e.response["Error"].get("Message")
        assert message == f"{name} for {ctx.account}", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
