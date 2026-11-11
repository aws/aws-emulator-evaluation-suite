"""code-repository-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-repository-create-describe-delete"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']

def _create_code_repository(ctx, name=None):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-coderepo-")
    arn = sm.create_code_repository(
        CodeRepositoryName=name,
        GitConfig={
            "RepositoryUrl": "https://example.com/sim2real/example-repo.git",
            "Branch": "main",
        },
        Tags=[{"Key": "sim2real", "Value": "code-repository-create-describe-delete"}],
    )["CodeRepositoryArn"]
    ctx.on_cleanup(lambda: _delete_code_repository_if_present(sm, name))
    return name, arn


def _delete_code_repository_if_present(sm, name):
    try:
        sm.delete_code_repository(CodeRepositoryName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCodeRepository is echoed by DescribeCodeRepository (ARN, name, RepositoryUrl), and after
    deletion DescribeCodeRepository and UpdateCodeRepository on the name fail with ValidationException
    and their exact messages."""
    sm = ctx.client("sagemaker")
    name, arn = _create_code_repository(ctx)

    desc = sm.describe_code_repository(CodeRepositoryName=name)
    assert desc["CodeRepositoryArn"] == arn, desc
    assert desc["CodeRepositoryName"] == name, desc
    assert (
        desc["GitConfig"]["RepositoryUrl"]
        == "https://example.com/sim2real/example-repo.git"
    ), desc["GitConfig"]

    sm.delete_code_repository(CodeRepositoryName=name)

    code, message = _error(
        lambda: sm.describe_code_repository(CodeRepositoryName=name)
    )
    assert code == "ValidationException", code
    expected_message = f"Cannot find CodeRepository: arn:aws:sagemaker:{ctx.region}:{ctx.account}:code-repository/{name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: sm.update_code_repository(CodeRepositoryName=name, GitConfig={})
    )
    assert update_code == "ValidationException", update_code
    expected_update_message = f"Cannot find CodeRepository: arn:aws:sagemaker:{ctx.region}:{ctx.account}:code-repository/{name}"
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
