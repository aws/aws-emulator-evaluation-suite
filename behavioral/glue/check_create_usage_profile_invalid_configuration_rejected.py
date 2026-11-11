"""create-usage-profile-invalid-configuration-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-usage-profile-invalid-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUsageProfile where a parameter's MinValue exceeds its MaxValue returns
    InvalidInputException and creates nothing, while a profile with a coherent range still
    creates successfully (positive control)."""
    glue = ctx.client("glue")

    bogus_name = ctx.unique_name("sim2real-glue-usageprofile-bad-")
    valid_name = ctx.unique_name("sim2real-glue-usageprofile-ok-")

    # numberOfWorkers must be paired with a workerType default when either is set, so both
    # are present here -- isolating the failure to the out-of-range Min > Max value itself.
    bad_config = {
        "JobConfiguration": {
            "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            "numberOfWorkers": {"DefaultValue": "5", "MinValue": "10", "MaxValue": "1"},
        }
    }
    code, message = _error(
        lambda: glue.create_usage_profile(Name=bogus_name, Configuration=bad_config)
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    expected = (
        "default value for parameter numberOfWorkers in JobConfiguration should be less than "
        "or equal to max value 1."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing was created under the rejected name.
    code, message = _error(lambda: glue.get_usage_profile(Name=bogus_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected = f"UsageProfile {bogus_name} does not exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a coherent configuration still creates successfully.
    good_config = {
        "JobConfiguration": {
            "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
        }
    }
    glue.create_usage_profile(
        Name=valid_name, Configuration=good_config, Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: glue.delete_usage_profile(Name=valid_name))
    got = glue.get_usage_profile(Name=valid_name)
    assert got["Name"] == valid_name


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
