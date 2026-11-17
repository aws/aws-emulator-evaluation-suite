"""image-config-working-directory-length-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-config-working-directory-length-limit-rejected"
GROUP = "packaging"
SERVICES = ["lambda"]

_OVER_LIMIT = "/" + "a" * 1000
_AT_LIMIT = "/" + "a" * 999

_WORKING_DIRECTORY_TOO_LONG = (
    "ValidationException",
    f"1 validation error detected: Value '{_OVER_LIMIT}' at 'imageConfig.workingDirectory' "
    "failed to satisfy constraint: Member must have length less than or equal to 1000",
)
_ROLE_CANNOT_BE_ASSUMED = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFunction refuses an ImageConfig.WorkingDirectory over 1000 characters before
    any resource lookup, and the same call at the 1000-character limit instead fails on
    the role, proving the length check is what drew the first refusal.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_ImageConfig.html
    """
    lam = ctx.client("lambda")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    bogus_image = (
        f"{ctx.account}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-nonexistent"
        f"@sha256:{'0' * 64}"
    )
    bogus_role = f"arn:{partition}:iam::{ctx.account}:role/sim2real-does-not-exist"

    def _create(working_directory, function_name):
        return lam.create_function(
            FunctionName=function_name,
            PackageType="Image",
            Code={"ImageUri": bogus_image},
            Role=bogus_role,
            ImageConfig={"WorkingDirectory": working_directory},
            Tags={"sim2real": CHECK},
        )

    over_name = ctx.unique_name("sim2real-behav-fn-")
    expect_error(lambda: _create(_OVER_LIMIT, over_name), *_WORKING_DIRECTORY_TOO_LONG)

    at_limit_name = ctx.unique_name("sim2real-behav-fn-")
    expect_error(lambda: _create(_AT_LIMIT, at_limit_name), *_ROLE_CANNOT_BE_ASSUMED)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
