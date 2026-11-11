"""op-contract-putImageScanningConfiguration."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putImageScanningConfiguration"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutImageScanningConfiguration flips scanOnPush and the change is durably reflected
    by DescribeRepositories; it raises RepositoryNotFoundException for an unknown repository."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    assert repo["imageScanningConfiguration"]["scanOnPush"] is False, (
        f"expected a freshly created repository to default scanOnPush to False, got "
        f"{repo['imageScanningConfiguration']['scanOnPush']!r}"
    )

    resp = ecr.put_image_scanning_configuration(
        repositoryName=name, imageScanningConfiguration={"scanOnPush": True}
    )
    assert resp["repositoryName"] == name, (
        f"expected PutImageScanningConfiguration to echo repositoryName={name!r}, "
        f"got {resp['repositoryName']!r}"
    )
    assert resp["imageScanningConfiguration"]["scanOnPush"] is True, (
        f"expected PutImageScanningConfiguration's own response to report scanOnPush=True, "
        f"got {resp['imageScanningConfiguration']['scanOnPush']!r}"
    )

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageScanningConfiguration"]["scanOnPush"] is True, (
        f"expected an independent DescribeRepositories read to durably reflect scanOnPush=True, "
        f"got {described['imageScanningConfiguration']['scanOnPush']!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    code, message = _error_code(
        lambda: ecr.put_image_scanning_configuration(
            repositoryName=missing_name, imageScanningConfiguration={"scanOnPush": True}
        )
    )
    assert code == "RepositoryNotFoundException", (
        f"expected PutImageScanningConfiguration on a nonexistent repository {missing_name!r} to "
        f"raise RepositoryNotFoundException, got error code {code!r}"
    )
    expected_message = (
        f"The repository with name '{missing_name}' does not exist in the registry with id "
        f"'{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
