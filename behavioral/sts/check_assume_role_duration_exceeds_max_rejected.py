"""assume-role-duration-exceeds-max-rejected."""
from __future__ import annotations

from botocore.config import Config

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-duration-exceeds-max-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DurationSeconds beyond the absolute service maximum (43200s) must be rejected."""

    sts = ctx.client("sts")

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

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _nonexistent_role_arn(account_id=None):
        # Well-formed ARN that refers to no real role: passes ARN pattern validation but
        # can never authorize, the right substitute for negative AssumeRole assertions.
        acct = account_id or _account_id()
        return f"arn:aws:iam::{acct}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"


    def _denied_message(role_arn):
        # STS names the calling identity and the role it refused to hand out.
        caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
        return (
            f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
            f"{role_arn}"
        )

    client = _unvalidated_client()
    role_arn = _nonexistent_role_arn()

    # Positive control: the SAME nonexistent-role call, with an in-bounds duration, must be
    # refused for lack of authorization (AccessDenied) rather than for a malformed request.
    # This isolates DurationSeconds as the one thing that flips the outcome below, ruling out
    # "rejects every AssumeRole to this role" as an alternative explanation.
    control_code, control_message = _refusal(
        lambda: client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            DurationSeconds=3600,
        )
    )
    assert control_code == "AccessDenied", (
        f"expected AccessDenied for the in-bounds-duration control call, got {control_code}"
    )
    assert control_message == _denied_message(role_arn), control_message

    code, message = _refusal(
        lambda: client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            DurationSeconds=999999,
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for DurationSeconds beyond the max, got {code}"
    )
    assert message == (
        "1 validation error detected: Value '999999' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 43200"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
