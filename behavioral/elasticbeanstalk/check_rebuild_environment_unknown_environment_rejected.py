"""rebuild-environment-unknown-environment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rebuild-environment-unknown-environment-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebuildEnvironment on a never-created environment name fails with InvalidParameterValue and the exact
    message, and no environment of that name appears."""
    eb = ctx.client("elasticbeanstalk")

    bogus_env_name = ctx.unique_name("sim2real-eb-ghost-")
    code, message = _error_code(lambda: eb.rebuild_environment(EnvironmentName=bogus_env_name))
    assert code == "InvalidParameterValue", (
        f"unexpected error code for a nonexistent environment: {code}"
    )
    expected = f"No Environment found for EnvironmentName = '{bogus_env_name}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The bogus name must never correspond to a real environment record (before or after).
    ghost = eb.describe_environments(EnvironmentNames=[bogus_env_name], IncludeDeleted=False)["Environments"]
    assert ghost == [], f"unexpected environment materialized for a bogus name: {ghost}"


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected success raises, so an
    emulator accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

