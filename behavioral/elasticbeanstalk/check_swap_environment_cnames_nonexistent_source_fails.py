"""swap-environment-cnames-nonexistent-source-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "swap-environment-cnames-nonexistent-source-fails"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a swap real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SwapEnvironmentCNAMEs between two never-created environments fails with InvalidParameterValue
    "source environment not found with Name: <source> in account '<account>'": the refusal names the
    source environment and never the destination."""
    eb = ctx.client("elasticbeanstalk")
    src = ctx.unique_name("sim2real-behav-eb-env-src-")
    dst = ctx.unique_name("sim2real-behav-eb-env-dst-")
    err = _err(
        lambda: eb.swap_environment_cnames(
            SourceEnvironmentName=src,
            DestinationEnvironmentName=dst,
        )
    )
    code, message = err.get("Code"), err.get("Message") or ""
    assert code == "InvalidParameterValue", (
        f"swapping CNAMEs of a nonexistent source environment must fail with "
        f"InvalidParameterValue, got {code!r} ({message!r})"
    )
    assert src in message and dst not in message, (
        f"the rejection must name the SOURCE environment {src!r} specifically, not the "
        f"destination {dst!r} -- proving the source lookup (not a generic refusal) is what "
        f"failed; got message {message!r}"
    )
    account = ctx.account
    expected = f"source environment not found with Name: {src} in account '{account}'"
    assert message == expected, f"expected {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
