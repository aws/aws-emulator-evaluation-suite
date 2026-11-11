"""list-channels-pagination-traverses-all."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-pagination-traverses-all"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels with maxResults=1 forces multiple pages; walking nextToken to
    exhaustion must surface every channel created in this run exactly once."""
    ivs = ctx.client("ivs")
    created_arns = set()
    for _ in range(3):
        name = ctx.unique_name("sim2real-ivs-page-")
        arn = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]["arn"]
        created_arns.add(arn)
        ctx.on_cleanup(lambda a=arn: ivs.delete_channel(arn=a))

    seen_arns: list[str] = []
    token = None
    pages = 0
    # Bounded: stop as soon as all 3 created channels are found, with a generous
    # cap on pages walked so a large pre-existing account inventory cannot hang this.
    while created_arns - set(seen_arns):
        pages += 1
        assert pages <= 2000, "did not find all created channels within a sane page bound"
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = ivs.list_channels(**kwargs)
        assert len(page["channels"]) <= 1, (
            f"maxResults=1 but page {pages} returned {len(page['channels'])} channels"
        )
        seen_arns.extend(c["arn"] for c in page["channels"])
        token = page.get("nextToken")
        if not token:
            break

    seen_set = set(seen_arns)
    # No ARN should repeat across pages.
    assert len(seen_arns) == len(seen_set), (
        f"duplicate arn(s) across pages: {len(seen_arns)} entries, {len(seen_set)} unique"
    )
    # Every channel created by this check must have been surfaced.
    missing = created_arns - seen_set
    assert not missing, f"channels created but never surfaced by ListChannels: {missing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
