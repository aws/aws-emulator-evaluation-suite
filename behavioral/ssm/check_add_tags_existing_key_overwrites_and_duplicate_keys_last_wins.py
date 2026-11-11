"""add-tags-existing-key-overwrites-and-duplicate-keys-last-wins."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-tags-existing-key-overwrites-and-duplicate-keys-last-wins"
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
    """AddTagsToResource replaces the value of an existing key rather than adding a second entry, and
    a key repeated within one request keeps its last value; the parameter version does not move.
    """
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-addtags-") + "/cfg"
    ssm.put_parameter(Name=name, Value="v1", Type="String",
                      Tags=[{"Key": "owner", "Value": "alpha"}, {"Key": "tier", "Value": "gold"}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))

    ssm.add_tags_to_resource(ResourceType="Parameter", ResourceId=name,
                             Tags=[{"Key": "owner", "Value": "beta"}])
    want = [{"Key": "owner", "Value": "beta"}, {"Key": "tier", "Value": "gold"}]
    assert _tags(ssm, name) == want, f"after re-adding owner tags are {_tags(ssm, name)!r}"

    ssm.add_tags_to_resource(ResourceType="Parameter", ResourceId=name,
                             Tags=[{"Key": "dup", "Value": "first"},
                                   {"Key": "dup", "Value": "last"}])
    want = [{"Key": "dup", "Value": "last"}, {"Key": "owner", "Value": "beta"},
            {"Key": "tier", "Value": "gold"}]
    got = _tags(ssm, name)
    assert got == want, f"after a request repeating dup tags are {got!r}, expected {want!r}"

    version = ssm.get_parameter(Name=name)["Parameter"]["Version"]
    assert version == 1, f"tagging moved the parameter to Version {version!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

