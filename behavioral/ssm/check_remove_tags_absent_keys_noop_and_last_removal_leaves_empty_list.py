"""remove-tags-absent-keys-noop-and-last-removal-leaves-empty-list."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-tags-absent-keys-noop-and-last-removal-leaves-empty-list"
GROUP = "tagging"
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


def _tags(ssm, resource_id: str) -> list:
    """The parameter's TagList sorted by key; tag order is not part of the contract."""
    tag_list = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=resource_id)["TagList"]
    return sorted(tag_list, key=lambda t: t["Key"])


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTagsFromResource drops present keys, ignores absent ones without an error, and removing
    the last key leaves an empty TagList on a parameter that still resolves.
    """
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-rmtags-") + "/cfg"
    ssm.put_parameter(Name=name, Value="v1", Type="String",
                      Tags=[{"Key": "keep", "Value": "1"}, {"Key": "drop", "Value": "2"}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))

    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name,
                                  TagKeys=["drop", "never-set"])
    assert _tags(ssm, name) == [{"Key": "keep", "Value": "1"}], (
        f"after removing a present and an absent key tags are {_tags(ssm, name)!r}"
    )

    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name,
                                  TagKeys=["never-set"])
    assert _tags(ssm, name) == [{"Key": "keep", "Value": "1"}], (
        f"removing only an absent key changed tags to {_tags(ssm, name)!r}"
    )

    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name, TagKeys=["keep"])
    resp = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)
    assert resp.get("TagList") == [], f"after removing every key the response is {resp!r}"

    param = ssm.get_parameter(Name=name)["Parameter"]
    assert (param["Value"], param["Version"]) == ("v1", 1), (
        f"tag removal changed the parameter to {param['Value']!r} v{param['Version']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

