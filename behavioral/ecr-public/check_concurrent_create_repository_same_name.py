"""concurrent-create-repository-same-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrent-create-repository-same-name"
GROUP = 'concurrency'
SERVICES = ['ecr-public']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """(concurrency) N racers calling CreateRepository with the identical name must result in exactly
    one success and the rest failing with RepositoryAlreadyExistsException, and DescribeRepositories
    (an independent read at the destination) must then show exactly one repository under that name."""
    from concurrent.futures import ThreadPoolExecutor

    from botocore.exceptions import ClientError

    ecr = ctx.client("ecr-public")
    name = ctx.unique_name("sim2real-behav-ecrpub-race-")
    n = 6

    def _cleanup():
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                raise

    # Registered before the race so a mid-race crash still tears down whichever racer won.
    ctx.on_cleanup(_cleanup)

    # One boto3 client, shared across the racers: boto3 clients are thread-safe for
    # concurrent calls, so a single client still fires N genuinely concurrent
    # CreateRepository requests at the same name.
    def attempt(idx: int):
        try:
            ecr.create_repository(repositoryName=name)
            return ("ok", None)
        except ClientError as e:
            return ("err", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    successes = [r for r in results if r[0] == "ok"]
    error_codes = [r[1] for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {results}"
    assert len(error_codes) == n - 1, f"expected {n - 1} errors, got {len(error_codes)}: {results}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    already_exists = (
        f"The repository with name '{name}' already exists in the registry with id '{account}'"
    )
    assert all(c == ("RepositoryAlreadyExistsException", already_exists) for c in error_codes), error_codes

    # Independent read at the destination, through DescribeRepositories rather than the
    # racers' own CreateRepository responses: exactly one repository must actually exist.
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert len(described) == 1, f"expected exactly 1 repository named {name!r}, got {described}"
    assert described[0]["repositoryName"] == name, (
        f"expected the described repository to be named {name!r}, got {described[0]!r}"
    )

    ecr.delete_repository(repositoryName=name)
    try:
        ecr.describe_repositories(repositoryNames=[name])
        raise AssertionError("expected RepositoryNotFoundException after delete, got success")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
        message = e.response["Error"].get("Message")
        assert message == (
            f"The repository with name '{name}' does not exist in the registry with id '{account}'"
        ), f"DescribeRepositories message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
