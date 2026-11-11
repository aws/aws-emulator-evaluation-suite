"""delete-launch-configuration-template-twice-returns-not-found."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-launch-configuration-template-twice-returns-not-found"
GROUP = "launch-configuration-templates"
SERVICES = ["drs"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "requires:drs-initialized",
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteLaunchConfigurationTemplate succeeds once, then a second delete of the same id
    is rejected as not found rather than silently succeeding again."""
    drs = ctx.client("drs")
    created = drs.create_launch_configuration_template(recoveryMode="FAST")
    template_id = created["launchConfigurationTemplate"]["launchConfigurationTemplateID"]

    drs.delete_launch_configuration_template(launchConfigurationTemplateID=template_id)

    code, message = _error(
        lambda: drs.delete_launch_configuration_template(launchConfigurationTemplateID=template_id)
    )
    assert code == "ResourceNotFoundException", f"second delete gave {code}: {message!r}"
    expected = f"Launch Configuration Template with Id: '{template_id}' was not found"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    describe = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[template_id]
    )
    assert describe["items"] == [], (
        f"template {template_id!r} still appears in a filtered describe after deletion: "
        f"{describe['items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
