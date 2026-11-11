"""list-templates-reflects-create-update-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-templates-reflects-create-update-delete"
GROUP = "state-machine"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTemplates membership and metadata (name, CreatedTimestamp)
    accurately reflect create, in-place update, and delete of a template
    across calls -- and CreatedTimestamp does not change on update."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-ses-tmpl-")

    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Original subject",
            "HtmlPart": "<html><body>original</body></html>",
            "TextPart": "original",
        }
    )
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            ses.delete_template(TemplateName=name)

    ctx.on_cleanup(_cleanup)

    listed = _find_template_metadata(ses, name)
    assert listed is not None, "created template not found in ListTemplates"
    created_ts_before = listed["CreatedTimestamp"]

    original = ses.get_template(TemplateName=name)["Template"]
    assert original["SubjectPart"] == "Original subject", (
        f"expected original SubjectPart, got {original['SubjectPart']!r}"
    )

    ses.update_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Updated subject",
            "HtmlPart": "<html><body>updated</body></html>",
            "TextPart": "updated",
        }
    )

    updated = ses.get_template(TemplateName=name)["Template"]
    assert updated["SubjectPart"] == "Updated subject", (
        f"expected updated SubjectPart, got {updated['SubjectPart']!r}"
    )
    assert updated["HtmlPart"] == "<html><body>updated</body></html>", (
        f"expected updated HtmlPart, got {updated['HtmlPart']!r}"
    )

    listed_after_update = _find_template_metadata(ses, name)
    assert listed_after_update is not None, "updated template disappeared from ListTemplates"
    assert listed_after_update["CreatedTimestamp"] == created_ts_before, (
        listed_after_update["CreatedTimestamp"],
        created_ts_before,
    )

    ses.delete_template(TemplateName=name)
    cleaned["done"] = True

    listed_after_delete = _find_template_metadata(ses, name)
    assert listed_after_delete is None, "deleted template still present in ListTemplates"

    try:
        ses.get_template(TemplateName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {}).get("Code")
        msg = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("expected GetTemplate on the deleted template to fail, but it SUCCEEDED")
    assert err == "TemplateDoesNotExist", (
        f"expected TemplateDoesNotExist reading deleted template, got {err!r}: {msg!r}"
    )
    expected_msg = f"Template {name} does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _find_template_metadata(ses, name):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ses.list_templates(**kwargs)
        for meta in resp["TemplatesMetadata"]:
            if meta["Name"] == name:
                return meta
        next_token = resp.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
