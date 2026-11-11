"""list-terminologies-reflects-created-terminology."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-terminologies-reflects-created-terminology"
GROUP = "control-plane"
SERVICES = ["translate"]


def _list_terminology_names(translate) -> list[str]:
    found_names = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 500}
        if next_token:
            kwargs["NextToken"] = next_token
        page = translate.list_terminologies(**kwargs)
        found_names.extend(t["Name"] for t in page["TerminologyPropertiesList"])
        next_token = page.get("NextToken")
        if not next_token:
            break
    return found_names


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTerminologies includes a just-created terminology by name, and drops it after delete."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nHello,Hola\n", "Format": "CSV"},
        Tags=[{"Key": "project", "Value": "sim2real"}],
    )

    def _cleanup() -> None:
        try:
            translate.delete_terminology(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    found_names = _list_terminology_names(translate)
    assert name in found_names, f"expected {name!r} in ListTerminologies, got {found_names!r}"

    translate.delete_terminology(Name=name)

    found_after_delete = _list_terminology_names(translate)
    assert name not in found_after_delete, (
        f"expected {name!r} absent from ListTerminologies after delete, got {found_after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
