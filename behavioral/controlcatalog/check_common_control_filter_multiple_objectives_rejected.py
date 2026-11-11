"""common-control-filter-multiple-objectives-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "common-control-filter-multiple-objectives-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]


def _error_code(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a filter real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects a multi-objective CommonControlFilter, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCommonControls rejects a CommonControlFilter with two Objectives ARNs with ValidationException
    "The provided filter is not valid. ...", and a one-ARN filter returns only that objective's controls."""
    cc = ctx.client("controlcatalog")

    objectives = cc.list_objectives(MaxResults=2).get("Objectives", [])
    assert len(objectives) >= 2, "need at least two distinct objectives to build a 2-element filter"
    arn_a, arn_b = objectives[0]["Arn"], objectives[1]["Arn"]

    code, message = _error_code(
        lambda: cc.list_common_controls(
            MaxResults=10, CommonControlFilter={"Objectives": [{"Arn": arn_a}, {"Arn": arn_b}]}
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a 2-element Objectives filter, got {code!r}"
    # AWS embeds the downstream service name and a per-request Request ID, so the stable prefix and suffix are exact.
    expected_prefix = "The provided filter is not valid. Ensure that each part of the filter is valid, and try again. (Service: "
    expected_suffix = ") (SDK Attempt Count: 1)"
    assert message.startswith(expected_prefix) and message.endswith(expected_suffix), (
        f"expected a message starting {expected_prefix!r} and ending {expected_suffix!r}, got {message!r}"
    )

    # Positive control: a single-element Objectives filter is accepted and correctly scopes results.
    response = cc.list_common_controls(
        MaxResults=10, CommonControlFilter={"Objectives": [{"Arn": arn_a}]}
    )
    common_controls = response.get("CommonControls", [])
    assert common_controls, "expected at least one common control for the chosen objective"
    for common_control in common_controls:
        assert common_control["Objective"]["Arn"] == arn_a, (
            f"expected every common control to be scoped to objective {arn_a!r}, "
            f"got {common_control['Objective']['Arn']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
