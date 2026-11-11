"""describe-instance-patches-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-patches-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancePatches with an unknown filter Key fails with ValidationException "Unknown
    Filter Key: NotARealFilterKey", while a valid filter on the same instance id returns an empty
    Patches page."""
    ssm = ctx.client("ssm")
    fake_instance_id = "mi-" + "0" * 17  # well-formed managed-instance id, never registered

    def _bad_filter():
        ssm.describe_instance_patches(
            InstanceId=fake_instance_id,
            Filters=[{"Key": "NotARealFilterKey", "Values": ["x"]}],
        )

    bad_filter_code, bad_filter_message = _error(_bad_filter)
    assert bad_filter_code == "ValidationException", (
        f"expected ValidationException, got {bad_filter_code}"
    )
    assert bad_filter_message == "Unknown Filter Key: NotARealFilterKey", bad_filter_message

    def _good_filter():
        return ssm.describe_instance_patches(
            InstanceId=fake_instance_id,
            Filters=[{"Key": "State", "Values": ["Installed"]}],
        )

    # A well-formed filter key against a syntactically-valid but never-registered
    # instance does not raise -- it resolves to an empty page, distinct from the
    # ValidationException the malformed filter key above triggers.
    good_filter_result = _good_filter()
    assert good_filter_result["Patches"] == [], (
        f"expected an empty Patches page for a never-registered instance, "
        f"got {good_filter_result['Patches']}"
    )

    # Positive control: another list call with no target requirements still works.
    positive = ssm.describe_patch_baselines()
    assert "BaselineIdentities" in positive, (
        f"expected a BaselineIdentities key in describe_patch_baselines response, "
        f"got keys {list(positive.keys())}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
