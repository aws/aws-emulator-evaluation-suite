"""list-environments-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-environments-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEnvironments refuses MaxResults=26 (above the documented 1-25) with a server-side
    ValidationException and its exact message rather than clamping it, while MaxResults=5 succeeds.
    """
    mwaa = ctx.client("mwaa")

    code, message = _error(lambda: mwaa.list_environments(MaxResults=26))
    assert code == "ValidationException", (
        f"expected ValidationException for MaxResults=26, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value '26' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 25"
    ), f"got message {message!r}"

    # Positive control: the identical operation with an in-range MaxResults succeeds.
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control, f"expected an Environments key, got {control!r}"
    assert len(control["Environments"]) <= 5, (
        f"expected at most 5 environments for MaxResults=5, got {len(control['Environments'])}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

