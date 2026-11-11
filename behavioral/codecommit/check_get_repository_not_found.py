"""get-repository-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-repository-not-found"
GROUP = 'error-semantics'
SERVICES = ['codecommit']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Positive control: GetRepository succeeds on a real repository. Negative:
    GetRepository on a name that was never created → RepositoryDoesNotExistException,
    proving the error is specific to the absent name and not a blanket rejection."""
    cc = ctx.client("codecommit")

    real_name = ctx.unique_name("sim2real-behav-real-")
    cc.create_repository(repositoryName=real_name)
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=real_name))

    control = cc.get_repository(repositoryName=real_name)["repositoryMetadata"]
    assert control["repositoryName"] == real_name, control

    missing_name = ctx.unique_name("sim2real-behav-missing-")
    try:
        result = cc.get_repository(repositoryName=missing_name)
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"GetRepository on a never-created name SUCCEEDED: {result!r}")
    assert code == "RepositoryDoesNotExistException", code
    assert message == f"{missing_name} for {ctx.account}", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
