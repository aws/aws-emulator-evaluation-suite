"""update-form-persists-field-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-form-persists-field-changes"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateForm persists a changed field label and CTA position, and GetForm reflects the
    changes afterwards."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-updform-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_form(
        appId=app_id,
        environmentName=_ENV,
        formToCreate={
            "name": name,
            "dataType": {"dataSourceType": "DataStore", "dataTypeName": "Post"},
            "formActionType": "create",
            "fields": {"title": {"label": "Title", "inputType": {"type": "SingleLineText"}}},
            "style": {},
            "sectionalElements": {},
            "schemaVersion": "1.0",
            "cta": {"position": "top"},
            "tags": {"owner": "sim2real"},
        },
    )["entity"]
    form_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_form(appId=app_id, environmentName=_ENV, id=form_id))

    updated = uib.update_form(
        appId=app_id,
        environmentName=_ENV,
        id=form_id,
        updatedForm={
            "name": name,
            "fields": {"title": {"label": "Post title", "inputType": {"type": "SingleLineText"}}},
            "cta": {"position": "bottom"},
        },
    )["entity"]
    assert updated["fields"]["title"]["label"] == "Post title", (
        f"UpdateForm response: expected fields.title.label='Post title', "
        f"got {updated['fields']['title']['label']!r}"
    )
    assert updated["cta"]["position"] == "bottom", (
        f"UpdateForm response: expected cta.position='bottom', got {updated['cta']['position']!r}"
    )

    fetched = uib.get_form(appId=app_id, environmentName=_ENV, id=form_id)["form"]
    assert fetched["fields"]["title"]["label"] == "Post title", (
        f"GetForm after update: expected fields.title.label='Post title', "
        f"got {fetched['fields']['title']['label']!r}"
    )
    assert fetched["cta"]["position"] == "bottom", (
        f"GetForm after update: expected cta.position='bottom', got {fetched['cta']['position']!r}"
    )


def _create_app(ctx):
    import random
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"owner": "sim2real"})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
