"""put-parameter-create-tags-survive-overwrites."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-create-tags-survive-overwrites"
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
    """Tags given at PutParameter create list exactly and survive overwrites that carry no tags.

    An overwrite with an empty Tags list counts as no tags: it lands and the tags stay.
    """
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-keeptags-") + "/cfg"
    created = [{"Key": "owner", "Value": "alpha"}, {"Key": "tier", "Value": "gold"}]
    ssm.put_parameter(Name=name, Value="v1", Type="String", Tags=created)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))
    assert _tags(ssm, name) == created, f"create-time tags list as {_tags(ssm, name)!r}"

    overwrites = [
        ("v2", {"Type": "String"}),
        ("v3", {}),
        ("v4", {"Type": "String", "Tags": []}),
    ]
    for expected_version, (value, kwargs) in enumerate(overwrites, start=2):
        version = ssm.put_parameter(Name=name, Value=value, Overwrite=True, **kwargs)["Version"]
        assert version == expected_version, (
            f"overwrite {sorted(kwargs)!r} answered Version {version!r}, expected {expected_version}"
        )
        assert _tags(ssm, name) == created, (
            f"after overwrite to {value!r} with {sorted(kwargs)!r} tags list as {_tags(ssm, name)!r}"
        )

    param = ssm.get_parameter(Name=name)["Parameter"]
    assert (param["Value"], param["Version"]) == ("v4", 4), (
        f"final parameter is {param['Value']!r} v{param['Version']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

