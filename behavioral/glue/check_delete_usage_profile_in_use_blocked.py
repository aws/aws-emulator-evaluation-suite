"""delete-usage-profile-in-use-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-usage-profile-in-use-blocked"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsageProfile rejects a reused Name without changing the existing profile; delete is
    idempotent and frees the name for reuse. AWS documents no delete-while-in-use block to assert.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_CreateUsageProfile.html
    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_DeleteUsageProfile.html
    """
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-usageprofile-")
    # Configuration keys are camelCase, and AWS rejects workerType without numberOfWorkers.
    original_config = {
        "JobConfiguration": {
            "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
            "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
        }
    }
    glue.create_usage_profile(Name=name, Configuration=original_config, Description="original")

    def _cleanup():
        try:
            glue.delete_usage_profile(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    original = glue.get_usage_profile(Name=name)
    assert original["Configuration"]["JobConfiguration"]["numberOfWorkers"]["DefaultValue"] == "2", original

    duplicate_config = {
        "JobConfiguration": {
            "numberOfWorkers": {"DefaultValue": "9", "MinValue": "1", "MaxValue": "10"},
            "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
        }
    }
    code = _error_code(
        lambda: glue.create_usage_profile(
            Name=name,
            Configuration=duplicate_config,
            Description="different config, same name",
        )
    )
    assert code == ("AlreadyExistsException", f"UsageProfile {name} already exists."), code

    unchanged = glue.get_usage_profile(Name=name)
    assert unchanged["Configuration"]["JobConfiguration"]["numberOfWorkers"]["DefaultValue"] == "2", unchanged
    assert unchanged["Description"] == "original", unchanged

    glue.delete_usage_profile(Name=name)
    not_found_code = _error_code(lambda: glue.get_usage_profile(Name=name))
    assert not_found_code == ("EntityNotFoundException", f"UsageProfile {name} does not exists"), not_found_code

    # Re-deleting a gone name is a no-op 200; EntityNotFoundException is not in its error surface.
    redelete_resp = glue.delete_usage_profile(Name=name)
    assert redelete_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, redelete_resp

    # The rejection was about the claimed name, so the same create succeeds once it is free.
    glue.create_usage_profile(Name=name, Configuration=duplicate_config, Description="different config, same name")
    reused = glue.get_usage_profile(Name=name)
    assert reused["Configuration"]["JobConfiguration"]["numberOfWorkers"]["DefaultValue"] == "9", reused
    assert reused["Description"] == "different config, same name", reused
    glue.delete_usage_profile(Name=name)
    reused_not_found_code = _error_code(lambda: glue.get_usage_profile(Name=name))
    assert reused_not_found_code == ("EntityNotFoundException", f"UsageProfile {name} does not exists"), reused_not_found_code

    other_name = ctx.unique_name("sim2real-usageprofile-ctrl-")
    glue.create_usage_profile(
        Name=other_name,
        Configuration={
            "JobConfiguration": {
                "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
                "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            }
        },
    )

    def _cleanup_other():
        try:
            glue.delete_usage_profile(Name=other_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_other)

    created = glue.get_usage_profile(Name=other_name)
    assert created["Name"] == other_name, created
    glue.delete_usage_profile(Name=other_name)
    other_not_found_code = _error_code(lambda: glue.get_usage_profile(Name=other_name))
    assert other_not_found_code == ("EntityNotFoundException", f"UsageProfile {other_name} does not exists"), other_not_found_code


# ===== helpers =====
def _error_code(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
