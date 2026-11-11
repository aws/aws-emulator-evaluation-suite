"""push-template-stale-version-update-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "push-template-stale-version-update-rejected"
GROUP = "template-versioning"
SERVICES = ["pinpoint"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Updating a push template by naming a version older than the latest is rejected and
    leaves that version's content untouched; updating the actual latest version still works.
    """
    pin = ctx.client("pinpoint")
    name = ctx.unique_name("sim2real-behav-pinpoint-push-tmpl-")

    pin.create_push_template(
        TemplateName=name, PushNotificationTemplateRequest={"Default": {"Body": "v1 body"}}
    )

    def undo():
        try:
            pin.delete_push_template(TemplateName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(undo)

    pin.update_push_template(
        TemplateName=name,
        CreateNewVersion=True,
        PushNotificationTemplateRequest={"Default": {"Body": "v2 body"}},
    )

    code, message = _error(
        lambda: pin.update_push_template(
            TemplateName=name,
            Version="1",
            PushNotificationTemplateRequest={"Default": {"Body": "stale write"}},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == "Updating the non latest template version is not allowed", (
        f"unexpected message {message!r}"
    )

    v1 = pin.get_push_template(TemplateName=name, Version="1")["PushNotificationTemplateResponse"]
    assert v1["Default"]["Body"] == "v1 body", (
        f"version 1's body is {v1['Default']['Body']!r}; the rejected stale write must not land"
    )

    # Positive control: updating the actual latest version (2) still succeeds.
    pin.update_push_template(
        TemplateName=name,
        Version="2",
        PushNotificationTemplateRequest={"Default": {"Body": "v2 body, revised"}},
    )
    v2 = pin.get_push_template(TemplateName=name, Version="2")["PushNotificationTemplateResponse"]
    assert v2["Default"]["Body"] == "v2 body, revised", (
        f"updating the latest version did not take effect, got {v2['Default']['Body']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
