"""assume-role-external-id-invalid-characters-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-external-id-invalid-characters-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; raises AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole refuses an ExternalId holding a space, which the externalIdType pattern
    forbids, with a ValidationError ahead of authorization against a target role."""

    # Client-side parameter validation off, so STS's own input validation answers instead of a
    # local ParamValidationError.
    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))

    # A well-formed ARN naming no real role: it passes ARN shape validation but can never
    # authorize, so a well-formed ExternalId on the same call is refused for lack of
    # authorization rather than for a malformed request.
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"
    session_name = ctx.unique_name("sim2real-behav-sess-")

    # Positive control: the identical call with a pattern-legal ExternalId reaches
    # authorization and is refused only for naming a role that does not exist, isolating the
    # disallowed character below as the one thing that changes the outcome.
    control_code, control_message = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            ExternalId="sim2real-valid-external-id",
        )
    )
    assert control_code == "AccessDenied", (
        f"expected AccessDenied for the legal-ExternalId control call, got {control_code}"
    )
    caller_arn = sts.get_caller_identity()["Arn"]
    assert control_message == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    ), control_message

    code, message = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            ExternalId="sim2real bad external id",
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for an ExternalId containing a space, got {code}"
    )
    assert message == (
        "1 validation error detected: Value 'sim2real bad external id' at 'externalId' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: "
        "[\\w+=,.@:\\/-]*"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
