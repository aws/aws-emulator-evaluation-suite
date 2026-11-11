"""describe-environment-health-unknown-env-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-environment-health-unknown-env-fails"
GROUP = 'environment-lifecycle'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEnvironmentHealth on a well-formed, never-created environment name fails with InvalidParameterValue
    and the exact message, and no environment of that name appears."""
    eb = ctx.client("elasticbeanstalk")
    # EnvironmentName is capped at 40 chars; ctx.unique_name appends 12 hex chars, so the prefix
    # must leave room -- a name that violates the length constraint gets ValidationError for the
    # WRONG reason (malformed input, not absence) and would silently defeat this check.
    name = ctx.unique_name("sim2real-eb-absent-")
    assert len(name) <= 40, f"generated EnvironmentName {name!r} ({len(name)} chars) exceeds AWS's own limit"
    code, message = _err(lambda: eb.describe_environment_health(EnvironmentName=name, AttributeNames=["All"]))
    assert code == "InvalidParameterValue", (
        f"DescribeEnvironmentHealth on a well-formed but never-created environment name must "
        f"fail with InvalidParameterValue, got {code!r}"
    )
    expected = f"No Environment found for EnvironmentName = '{name}'."
    assert message == expected, (
        f"DescribeEnvironmentHealth on a never-created environment must say {expected!r}, "
        f"got {message!r}"
    )

    # Independent second observable: the name must never correspond to a real environment record.
    ghost = eb.describe_environments(EnvironmentNames=[name], IncludeDeleted=False)["Environments"]
    assert ghost == [], f"unexpected environment materialized for a never-created name: {ghost}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
