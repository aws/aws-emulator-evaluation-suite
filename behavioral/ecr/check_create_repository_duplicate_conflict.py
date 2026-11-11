"""create-repository-duplicate-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it unexpectedly succeeded: {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_if_present(ecr, name))
    return resp["repository"]

def _delete_repo_if_present(ecr, name):
    """Teardown: force-delete `name`, tolerating a repository the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise

def _repo_absent(ecr, name) -> bool:
    try:
        ecr.describe_repositories(repositoryNames=[name])
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException"
    return False

def _wait_repo_absent(ecr, name, *, timeout_s=30.0, interval_s=2.0) -> bool:
    """Bounded retry: True once an independent read confirms `name` is gone, False on timeout."""
    deadline = time.monotonic() + timeout_s
    while not _repo_absent(ecr, name):
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(interval_s, deadline - time.monotonic()))
    return True

CHECK = "create-repository-duplicate-conflict"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository on an existing name MUST fail with RepositoryAlreadyExistsException and
    must not disturb the existing repository. Deleting that repository frees the name, and the
    identical CreateRepository call MUST then succeed."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    repo1 = _create_repo(ecr, ctx, name, tags=[{"Key": "sim2real", "Value": CHECK}])

    code, message = _error(lambda: ecr.create_repository(repositoryName=name))
    assert code == "RepositoryAlreadyExistsException", f"expected RepositoryAlreadyExistsException, got {code}"
    expected = (
        f"The repository with name '{name}' already exists in the registry with id '{ctx.account}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    desc = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert len(desc) == 1, (
        f"expected exactly one repository named {name} after the rejected duplicate, got {len(desc)}"
    )
    assert desc[0]["repositoryArn"] == repo1["repositoryArn"], (
        f"duplicate create must not replace the existing repository: "
        f"expected arn {repo1['repositoryArn']}, got {desc[0]['repositoryArn']}"
    )

    ecr.delete_repository(repositoryName=name, force=True)
    assert _wait_repo_absent(ecr, name), f"expected {name} to become absent within 30s of delete"

    repo2 = _create_repo(ecr, ctx, name)
    assert repo2["repositoryName"] == name, (
        f"expected the freed name {name} to be reusable, got {repo2['repositoryName']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
