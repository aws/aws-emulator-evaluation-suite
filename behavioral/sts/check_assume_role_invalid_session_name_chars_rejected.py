"""assume-role-invalid-session-name-chars-rejected."""
from __future__ import annotations

from botocore.config import Config

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-invalid-session-name-chars-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RoleSessionName containing characters outside the allowed pattern must be rejected."""

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

    # Positive control: the same well-formed-but-nonexistent role ARN with a VALID RoleSessionName
    # reaches AccessDenied, not ValidationError. Without this, a target that rejects every
    # AssumeRole call from this client -- for any reason -- would score identically to one that
    # specifically validates RoleSessionName chars.
    control_code, control_message = _refusal(
        lambda: client.assume_role(
            RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert control_code == "AccessDenied", (
        f"positive control: expected AccessDenied for a valid RoleSessionName against "
        f"a nonexistent role, got {control_code}"
    )
    assert control_message == _denied_message(role_arn), control_message

    code, message = _refusal(
        lambda: client.assume_role(RoleArn=role_arn, RoleSessionName="bad session name!")
    )
    assert code == "ValidationError", (
        f"expected ValidationError for invalid RoleSessionName characters, got {code}"
    )
    assert message == (
        "1 validation error detected: Value 'bad session name!' at 'roleSessionName' failed to "
        r"satisfy constraint: Member must satisfy regular expression pattern: [\w+=,.@-]*"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
