"""tags-do-not-survive-parameter-delete-and-recreate-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-do-not-survive-parameter-delete-and-recreate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _tags(ssm, resource_id: str) -> list:
    """The parameter's TagList sorted by key; tag order is not part of the contract."""
    tag_list = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=resource_id)["TagList"]
    return sorted(tag_list, key=lambda t: t["Key"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteParameter, tag calls on the name answer InvalidResourceId, and a parameter
    re-created under that name starts with an empty TagList.
    """
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-deltags-") + "/cfg"
    created = [{"Key": "owner", "Value": "alpha"}]
    ssm.put_parameter(Name=name, Value="v1", Type="String", Tags=created)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))
    assert _tags(ssm, name) == created, f"control: tags list as {_tags(ssm, name)!r}"

    ssm.delete_parameter(Name=name)
    for op, fn in (
        ("ListTagsForResource",
         lambda: ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)),
        ("RemoveTagsFromResource",
         lambda: ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name,
                                               TagKeys=["owner"])),
        ("AddTagsToResource",
         lambda: ssm.add_tags_to_resource(ResourceType="Parameter", ResourceId=name,
                                          Tags=[{"Key": "owner", "Value": "beta"}])),
    ):
        got = _error(fn)
        assert got == ("InvalidResourceId", ""), f"{op} on the deleted name gave {got!r}"

    ssm.put_parameter(Name=name, Value="v1-again", Type="String")
    param = ssm.get_parameter(Name=name)["Parameter"]
    assert (param["Value"], param["Version"]) == ("v1-again", 1), (
        f"re-created parameter is {param['Value']!r} v{param['Version']}"
    )
    assert _tags(ssm, name) == [], f"re-created parameter inherited tags {_tags(ssm, name)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

