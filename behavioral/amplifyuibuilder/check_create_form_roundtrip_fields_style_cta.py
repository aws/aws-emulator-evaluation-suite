"""create-form-roundtrip-fields-style-cta."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-form-roundtrip-fields-style-cta"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateForm persists fields, style, sectional elements, CTA buttons and label decorator,
    and GetForm returns the exact same configuration back."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-form-").replace("-", "")
    name = name[0].upper() + name[1:]

    form_to_create = {
        "name": name,
        "dataType": {"dataSourceType": "DataStore", "dataTypeName": "Post"},
        "formActionType": "create",
        "fields": {
            "title": {
                "label": "Title",
                "inputType": {"type": "SingleLineText", "required": True},
                "position": {"fixed": "first"},
            }
        },
        "style": {
            "horizontalGap": {"value": "8px"},
            "verticalGap": {"value": "8px"},
            "outerPadding": {"value": "16px"},
        },
        "sectionalElements": {
            "heading1": {"type": "Heading", "level": 2, "text": "New Post"}
        },
        "schemaVersion": "1.0",
        "cta": {
            "position": "bottom",
            "submit": {"children": "Submit", "excluded": False},
        },
        "labelDecorator": "required",
    }

    created = uib.create_form(appId=app_id, environmentName=_ENV, formToCreate=form_to_create)[
        "entity"
    ]
    form_id = created["id"]

    got = uib.get_form(appId=app_id, environmentName=_ENV, id=form_id)["form"]

    assert got["name"] == name, f"expected name={name!r}, got {got['name']!r}"
    assert got["dataType"] == {"dataSourceType": "DataStore", "dataTypeName": "Post"}, (
        f"expected dataType DataStore/Post, got {got['dataType']!r}"
    )
    assert got["fields"]["title"]["label"] == "Title", (
        f"expected fields.title.label='Title', got {got['fields']['title']['label']!r}"
    )
    assert got["fields"]["title"]["inputType"]["type"] == "SingleLineText", (
        "expected fields.title.inputType.type='SingleLineText', got "
        f"{got['fields']['title']['inputType']['type']!r}"
    )
    assert got["fields"]["title"]["inputType"]["required"] is True, (
        f"expected fields.title.inputType.required=True, got {got['fields']['title']['inputType']['required']!r}"
    )
    assert got["fields"]["title"]["position"] == {"fixed": "first"}, (
        f"expected fields.title.position={{'fixed': 'first'}}, got {got['fields']['title']['position']!r}"
    )
    assert got["style"]["horizontalGap"]["value"] == "8px", (
        f"expected style.horizontalGap.value='8px', got {got['style']['horizontalGap']['value']!r}"
    )
    assert got["sectionalElements"]["heading1"]["text"] == "New Post", (
        f"expected sectionalElements.heading1.text='New Post', got {got['sectionalElements']['heading1']['text']!r}"
    )
    assert got["sectionalElements"]["heading1"]["level"] == 2, (
        f"expected sectionalElements.heading1.level=2, got {got['sectionalElements']['heading1']['level']!r}"
    )
    assert got["cta"]["position"] == "bottom", (
        f"expected cta.position='bottom', got {got['cta']['position']!r}"
    )
    assert got["cta"]["submit"]["children"] == "Submit", (
        f"expected cta.submit.children='Submit', got {got['cta']['submit']['children']!r}"
    )
    assert got["labelDecorator"] == "required", (
        f"expected labelDecorator='required', got {got['labelDecorator']!r}"
    )

    # teardown is a free negative assertion: the deleted form is gone via the same
    # independent read path that just proved its configuration round-tripped.
    uib.delete_form(appId=app_id, environmentName=_ENV, id=form_id)
    err = _error(lambda: uib.get_form(appId=app_id, environmentName=_ENV, id=form_id))
    assert err["Code"] == "404", (
        f"expected GetForm on the just-deleted form {form_id!r} to be rejected with "
        f"botocore code '404', got {err!r}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real": CHECK})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
