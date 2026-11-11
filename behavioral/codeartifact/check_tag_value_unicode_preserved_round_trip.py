"""tag-value-unicode-preserved-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-preserved-round-trip"
GROUP = "server-side"
SERVICES = ["codeartifact"]

TAG_VALUE = "\u65e5\u672c\u8a9e-\u00dcn\u00efc\u00f6de-\u4e2d\u6587-\u0440\u0443\u0441\u0441\u043a\u0438\u0439"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing multi-byte unicode characters, written via TagResource
    on a domain, is returned character-for-character unchanged by
    ListTagsForResource.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-catagu-")
    resp = ca.create_domain(domain=domain)
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    domain_arn = resp["domain"]["arn"]

    ca.tag_resource(resourceArn=domain_arn, tags=[{"key": "purpose", "value": TAG_VALUE}])

    tags = ca.list_tags_for_resource(resourceArn=domain_arn)["tags"]
    matching = [t for t in tags if t["key"] == "purpose"]
    assert len(matching) == 1, f"expected exactly one 'purpose' tag, got {tags}"
    assert matching[0]["value"] == TAG_VALUE, (
        f"expected the tag value round-tripped unchanged, got {matching[0]['value']!r} "
        f"instead of {TAG_VALUE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
