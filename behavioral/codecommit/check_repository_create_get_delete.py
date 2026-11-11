"""repository-create-get-delete."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repository-create-get-delete"
GROUP = 'lifecycle'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRepository → GetRepository → DeleteRepository is a full lifecycle;
    the ARN/name round-trip and a terminal removal (subsequent Get →
    RepositoryDoesNotExistException, and a mutation on the dead id also fails)."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(
        repositoryName=ctx.unique_name("sim2real-behav-repo-"), tags={"sim2real": "behav"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    name = meta["repositoryName"]
    expected_arn = f"arn:aws:codecommit:{ctx.region}:{ctx.account}:{name}"
    assert meta["Arn"] == expected_arn, f"expected Arn {expected_arn}, got {meta['Arn']}"

    got = cc.get_repository(repositoryName=name)["repositoryMetadata"]
    assert got["repositoryName"] == name, f"expected repositoryName {name}, got {got}"
    assert got["Arn"] == meta["Arn"], f"expected Arn {meta['Arn']}, got {got}"

    # use leg: a commit written through PutFile reads back byte-exact through GetFile
    content = f"sim2real {uuid.uuid4().hex}\n".encode()
    put = cc.put_file(
        repositoryName=name, branchName="main", fileContent=content, filePath="sim2real.txt"
    )
    fetched = cc.get_file(repositoryName=name, filePath="sim2real.txt", commitSpecifier="main")
    assert fetched["fileContent"] == content, (
        f"GetFile must return the committed bytes, expected {content!r} got {fetched['fileContent']!r}"
    )
    assert fetched["commitId"] == put["commitId"], (
        f"GetFile commitId must equal PutFile's, expected {put['commitId']!r} got {fetched['commitId']!r}"
    )

    cc.delete_repository(repositoryName=name)

    def _assert_not_found(fn, what):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        else:
            raise AssertionError(f"{what}: expected RepositoryDoesNotExistException, the call SUCCEEDED: {result!r}")
        assert err.get("Code") == "RepositoryDoesNotExistException", (
            f"{what}: expected RepositoryDoesNotExistException, got {err.get('Code')!r}"
        )
        assert status == 400, f"{what}: expected HTTP 400, got {status}"
        expected_message = f"{name} for {ctx.account}"
        assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'

    _assert_not_found(lambda: cc.get_repository(repositoryName=name), "GetRepository on the deleted repository")

    listed = []
    for page in cc.get_paginator("list_repositories").paginate():
        listed.extend(r["repositoryName"] for r in page.get("repositories", []))
    assert name not in listed, "ListRepositories still holds the deleted repository"

    _assert_not_found(
        lambda: cc.update_repository_description(repositoryName=name, repositoryDescription="post-delete"),
        "UpdateRepositoryDescription on the deleted repository",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
