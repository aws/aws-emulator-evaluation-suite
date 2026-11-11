"""delete-usage-profile-missing-name-is-idempotent-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-usage-profile-missing-name-is-idempotent-noop"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUsageProfile is idempotent: deleting a never-created name, or an existing profile a second
    time, returns an empty 200, while the first delete of an existing profile really removes it."""
    glue = ctx.client("glue")

    real_name = ctx.unique_name("sim2real-glue-usageprofile-real-")
    bogus_name = ctx.unique_name("sim2real-glue-usageprofile-missing-")

    config = {
        "JobConfiguration": {
            "workerType": {"DefaultValue": "G.1X", "AllowedValues": ["G.1X", "G.2X"]},
            "numberOfWorkers": {"DefaultValue": "2", "MinValue": "1", "MaxValue": "10"},
        }
    }

    glue.create_usage_profile(Name=real_name, Configuration=config, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_profile_ignore(glue, real_name))

    # DeleteUsageProfile on a name that was never created is a no-op success, not an error --
    # confirmed empirically (EntityNotFoundException is not even in its documented error list).
    resp = glue.delete_usage_profile(Name=bogus_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from a no-op delete of a never-created name, got {resp['ResponseMetadata']}"
    )

    # Effect absent / unaffected: the real profile that does exist is untouched by the
    # no-op delete of the bogus name.
    still_there = glue.get_usage_profile(Name=real_name)
    assert still_there["Name"] == real_name, (
        f"expected {real_name} untouched by the bogus-name delete, got {still_there!r}"
    )

    # Positive control: the profile that genuinely exists is actually removed by delete.
    glue.delete_usage_profile(Name=real_name)
    code = _error_code(lambda: glue.get_usage_profile(Name=real_name))
    assert code == ("EntityNotFoundException", f"UsageProfile {real_name} does not exists"), f"expected EntityNotFoundException, got {code}"

    # Deleting the now-gone profile a second time is still a no-op success, not an error --
    # DeleteUsageProfile's idempotency does not depend on whether the name was ever valid.
    resp = glue.delete_usage_profile(Name=real_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from a second no-op delete of an already-gone name, got {resp['ResponseMetadata']}"
    )

    # Terminal read, independent of the mutating delete calls above: the second delete had
    # no side effect either -- the profile is still gone, not resurrected or half-restored.
    code_after_second_delete = _error_code(lambda: glue.get_usage_profile(Name=real_name))
    assert code_after_second_delete == ("EntityNotFoundException", f"UsageProfile {real_name} does not exists"), (
        f"expected the profile to remain absent after the second no-op delete, "
        f"got {code_after_second_delete}"
    )


# ===== helpers =====
def _error_code(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_profile_ignore(glue, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_usage_profile(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


