"""list-common-controls-multiple-objectives-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-common-controls-multiple-objectives-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCommonControls rejects a CommonControlFilter.Objectives with two ARNs with ValidationException
    "The provided filter is not valid. ...", while a one-ARN filter returns only that objective's
    controls."""
    cc = ctx.client("controlcatalog")

    objectives = cc.list_objectives(MaxResults=2)["Objectives"]
    assert len(objectives) >= 2, "need at least 2 distinct objectives in the catalog for this check"
    arn1, arn2 = objectives[0]["Arn"], objectives[1]["Arn"]

    ok = cc.list_common_controls(CommonControlFilter={"Objectives": [{"Arn": arn1}]})
    common_controls = ok.get("CommonControls", [])
    for common_control in common_controls:
        assert common_control["Objective"]["Arn"] == arn1, (
            f"single-objective filter returned a control scoped to "
            f"{common_control['Objective']['Arn']!r}, expected {arn1!r}"
        )

    code, message = _error_code(
        lambda: cc.list_common_controls(CommonControlFilter={"Objectives": [{"Arn": arn1}, {"Arn": arn2}]})
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # AWS embeds the downstream service name and a per-request Request ID, so the stable prefix and suffix are exact.
    expected_prefix = "The provided filter is not valid. Ensure that each part of the filter is valid, and try again. (Service: "
    expected_suffix = ") (SDK Attempt Count: 1)"
    assert message.startswith(expected_prefix) and message.endswith(expected_suffix), (
        f"expected a message starting {expected_prefix!r} and ending {expected_suffix!r}, got {message!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a multi-objective filter real AWS refuses is the strongest signal
    available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects a multi-objective CommonControlFilter, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
