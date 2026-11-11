"""deleting-configuration-set-eventually-clears-protect-configuration-association."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-configuration-set-eventually-clears-protect-configuration-association"
GROUP = "protect-configuration"
SERVICES = ["pinpoint-sms-voice-v2"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a configuration set clears its protect-configuration association, even
    when the conflict that association causes has not yet cleared on the first retry.
    """
    c = ctx.client("pinpoint-sms-voice-v2")
    cs_name = ctx.unique_name("sim2real-behav-pinpoint-cs-")
    pc = c.create_protect_configuration()["ProtectConfigurationId"]
    ctx.on_cleanup(
        _teardown(
            lambda: c.delete_protect_configuration(ProtectConfigurationId=pc),
            "ResourceNotFoundException",
        )
    )

    c.create_configuration_set(ConfigurationSetName=cs_name)
    ctx.on_cleanup(
        _teardown(
            lambda: c.delete_configuration_set(ConfigurationSetName=cs_name),
            "ResourceNotFoundException",
        )
    )

    c.associate_protect_configuration(ProtectConfigurationId=pc, ConfigurationSetName=cs_name)
    c.delete_configuration_set(ConfigurationSetName=cs_name)

    expected_conflict = (
        f'Conflict Occurred - Reason="PROTECT_CONFIGURATION_ASSOCIATED_WITH_CONFIGURATION_SET" '
        f'ResourceType="protect-configuration" ResourceId="{pc}"'
    )
    deadline = time.monotonic() + 60
    attempts = 0
    while True:
        attempts += 1
        try:
            c.delete_protect_configuration(ProtectConfigurationId=pc)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "ConflictException" or message != expected_conflict:
                raise AssertionError(
                    f"deleting the protect configuration failed with {code!r}: {message!r}, "
                    f"not the exact association conflict this check tolerates: {expected_conflict!r}"
                )
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"the association to the deleted configuration set {cs_name!r} never cleared "
                    f"after {attempts} attempt(s) over 60s; last error: {message!r}"
                )
            time.sleep(1)

    expected_not_found = (
        f'Resource Not Found - ResourceType="protect-configuration" ResourceId="{pc}"'
    )
    code, message = None, None
    try:
        c.describe_protect_configurations(ProtectConfigurationIds=[pc])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    assert code == "ResourceNotFoundException" and message == expected_not_found, (
        f"expected the deleted protect configuration {pc!r} to read back as not found with "
        f"{expected_not_found!r}, got code {code!r} message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
