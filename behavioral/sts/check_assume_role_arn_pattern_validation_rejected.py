"""assume-role-arn-pattern-validation-rejected."""
from __future__ import annotations

from botocore.config import Config

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-arn-pattern-validation-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A RoleArn that doesn't match the ARN pattern must be rejected with ValidationError
    (distinct from AccessDenied for a well-formed-but-nonexistent/untrusted ARN)."""

    def _unvalidated_client(service="sts"):
        # Client-side parameter validation off, so the SERVICE's own input validation answers
        # instead of a local ParamValidationError.
        return ctx.client(
            service, config=Config(retries={"max_attempts": 1}, parameter_validation=False)
        )

    def _refusal(fn):
        """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

    def _nonexistent_role_arn():
        # Well-formed ARN that refers to no real role: passes ARN pattern validation but
        # can never authorize — the positive control for "reaches authorization", distinct
        # from a malformed ARN that must be rejected before authorization is even attempted.
        account_id = ctx.client("sts").get_caller_identity()["Account"]
        return f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"


    def _denied_message(role_arn):
        # STS names the calling identity and the role it refused to hand out.
        caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
        return (
            f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
            f"{role_arn}"
        )

    client = _unvalidated_client()

    control_arn = _nonexistent_role_arn()
    control_code, control_message = _refusal(
        lambda: client.assume_role(
            RoleArn=control_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert control_code == "AccessDenied", (
        "positive control: a well-formed but nonexistent RoleArn must clear pattern "
        f"validation and reach authorization as AccessDenied, got {control_code}"
    )
    assert control_message == _denied_message(control_arn), control_message

    code, message = _refusal(
        lambda: client.assume_role(
            RoleArn="not-an-arn", RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert code == "ValidationError", f"expected ValidationError for malformed RoleArn, got {code}"
    assert message == (
        "1 validation error detected: Value 'not-an-arn' at 'roleArn' failed to satisfy "
        "constraint: Member must have length greater than or equal to 20"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
