"""create-app-allows-duplicate-names-with-distinct-ids."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-allows-duplicate-names-with-distinct-ids"
GROUP = "app-lifecycle"
SERVICES = ["pinpoint"]


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
    """CreateApp does not enforce Name uniqueness: two apps sharing a Name mint distinct
    Ids, and GetApps lists both of them under that shared Name.

    Reference: https://docs.aws.amazon.com/pinpoint/latest/apireference/apps.html
    """
    pin = ctx.client("pinpoint")
    shared_name = ctx.unique_name("sim2real-behav-dupname-")

    first = pin.create_app(CreateApplicationRequest={"Name": shared_name})["ApplicationResponse"]
    ctx.on_cleanup(
        _teardown(lambda: pin.delete_app(ApplicationId=first["Id"]), "NotFoundException")
    )
    second = pin.create_app(CreateApplicationRequest={"Name": shared_name})["ApplicationResponse"]
    ctx.on_cleanup(
        _teardown(lambda: pin.delete_app(ApplicationId=second["Id"]), "NotFoundException")
    )

    assert first["Name"] == shared_name, f"expected Name {shared_name!r}, got {first['Name']!r}"
    assert second["Name"] == shared_name, f"expected Name {shared_name!r}, got {second['Name']!r}"
    assert first["Id"] != second["Id"], (
        f"a duplicate-name create must mint its own Id, got {first['Id']!r} twice"
    )
    assert first["Arn"] != second["Arn"], (
        f"a duplicate-name create must mint its own Arn, got {first['Arn']!r} twice"
    )

    names_to_ids: dict[str, set[str]] = {}
    token = None
    while True:
        kwargs = {"Token": token} if token else {}
        page = pin.get_apps(**kwargs)["ApplicationsResponse"]
        for app in page.get("Item", []):
            names_to_ids.setdefault(app["Name"], set()).add(app["Id"])
        token = page.get("NextToken")
        if not token:
            break

    listed = names_to_ids.get(shared_name, set())
    assert listed == {first["Id"], second["Id"]}, (
        f"expected GetApps to list exactly {{first['Id'], second['Id']}} under {shared_name!r}, "
        f"got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
