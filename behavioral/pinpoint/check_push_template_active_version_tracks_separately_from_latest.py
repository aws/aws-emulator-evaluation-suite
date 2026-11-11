"""push-template-active-version-tracks-separately-from-latest."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "push-template-active-version-tracks-separately-from-latest"
GROUP = "template-versioning"
SERVICES = ["pinpoint"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new template version never becomes active on its own; a versionless read keeps
    returning the active version until UpdateTemplateActiveVersion repoints it.
    """
    pin = ctx.client("pinpoint")
    name = ctx.unique_name("sim2real-behav-pinpoint-push-tmpl-")

    pin.create_push_template(
        TemplateName=name, PushNotificationTemplateRequest={"Default": {"Body": "v1 body"}}
    )
    ctx.on_cleanup(_teardown_delete(pin, name))

    pin.update_push_template(
        TemplateName=name,
        CreateNewVersion=True,
        PushNotificationTemplateRequest={"Default": {"Body": "v2 body"}},
    )

    versions = {
        item["Version"]
        for item in pin.list_template_versions(TemplateName=name, TemplateType="PUSH")[
            "TemplateVersionsResponse"
        ]["Item"]
    }
    assert versions == {"1", "2"}, f"expected versions 1 and 2, got {sorted(versions)!r}"

    still_v1 = pin.get_push_template(TemplateName=name)["PushNotificationTemplateResponse"]
    assert still_v1["Version"] == "1", (
        f"creating version 2 changed the active version to {still_v1['Version']!r}, "
        f"expected it to stay '1'"
    )
    assert still_v1["Default"]["Body"] == "v1 body", (
        f"active version's body is {still_v1['Default']['Body']!r}, expected the v1 body"
    )

    explicit_v2 = pin.get_push_template(TemplateName=name, Version="2")[
        "PushNotificationTemplateResponse"
    ]
    assert explicit_v2["Default"]["Body"] == "v2 body", (
        f"explicit version 2 read returned {explicit_v2['Default']['Body']!r}, expected the v2 body"
    )

    pin.update_template_active_version(
        TemplateName=name,
        TemplateType="PUSH",
        TemplateActiveVersionRequest={"Version": "2"},
    )
    now_v2 = pin.get_push_template(TemplateName=name)["PushNotificationTemplateResponse"]
    assert now_v2["Version"] == "2", (
        f"after repointing active to version 2, a versionless read returned {now_v2['Version']!r}"
    )
    assert now_v2["Default"]["Body"] == "v2 body", (
        f"versionless read body is {now_v2['Default']['Body']!r}, expected the v2 body"
    )


def _teardown_delete(pin, name):
    def undo():
        try:
            pin.delete_push_template(TemplateName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    return undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
