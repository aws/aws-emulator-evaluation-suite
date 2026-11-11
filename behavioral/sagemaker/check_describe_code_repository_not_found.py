"""describe-code-repository-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-code-repository-not-found"
GROUP = 'error-semantics'
SERVICES = ['sagemaker']

def _error_code_and_message(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describing a never-created CodeRepository raises ValidationException.

    Empirical (wire): SageMaker surfaces "Cannot find CodeRepository" as a
    ValidationException rather than a dedicated not-found type.
    """
    sm = ctx.client("sagemaker")
    missing = ctx.unique_name("sim2real-behav-" + "missing-coderepo-")
    code, message = _error_code_and_message(
        lambda: sm.describe_code_repository(CodeRepositoryName=missing)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = f"Cannot find CodeRepository: arn:aws:sagemaker:{ctx.region}:{ctx.account}:code-repository/{missing}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
