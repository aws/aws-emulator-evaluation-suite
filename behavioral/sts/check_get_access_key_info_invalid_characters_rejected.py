"""get-access-key-info-invalid-characters-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-access-key-info-invalid-characters-rejected"
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
    """GetAccessKeyInfo refuses an AccessKeyId holding a character outside [A-Za-z0-9_], even
    at a length the id type otherwise allows, with the exact pattern-violation message."""

    # Client-side parameter validation off, so STS's own input validation answers instead of a
    # local ParamValidationError.
    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))

    # Positive control: a real, well-formed temporary access key id of the same minted shape
    # resolves to this account, isolating the stray character below as the one thing that flips
    # the outcome.
    minted = sts.get_session_token()["Credentials"]["AccessKeyId"]
    control = sts.get_access_key_info(AccessKeyId=minted)
    assert control["Account"] == ctx.account, (
        f"expected the minted key to resolve to {ctx.account!r}, got {control['Account']!r}"
    )

    bad_key_id = minted[:-1] + "!"
    code, message = _refusal(lambda: sts.get_access_key_info(AccessKeyId=bad_key_id))
    assert code == "ValidationError", (
        f"expected ValidationError for an AccessKeyId with a disallowed character, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{bad_key_id}' at 'accessKeyId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w]*"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
