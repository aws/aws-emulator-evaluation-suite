"""get-outpost-resolver-not-found-after-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-outpost-resolver-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Delete and Get on a never-created OutpostResolverId both return HTTP 200 without
    ResourceNotFoundException; Get omits OutpostResolver and the id is absent from the list.
    """
    # The model lists ResourceNotFoundException for both, but AWS does not raise it for this id.
    # A create-then-delete flow is impossible: CreateOutpostResolver needs a physical Outpost.
    client = ctx.client("route53resolver")
    bogus_id = ctx.unique_name("sim2real-behav-outpost-")

    delete_resp = client.delete_outpost_resolver(Id=bogus_id)
    assert delete_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeleteOutpostResolver on a never-created id to succeed idempotently, "
        f"got {delete_resp!r}"
    )

    get_resp = client.get_outpost_resolver(Id=bogus_id)
    assert get_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected GetOutpostResolver on a never-created id to return 200, got {get_resp!r}"
    )
    assert "OutpostResolver" not in get_resp, (
        f"expected no OutpostResolver field in the response for a never-created id, "
        f"got {get_resp!r}"
    )

    remaining = client.list_outpost_resolvers().get("OutpostResolvers", [])
    assert not any(o["Id"] == bogus_id for o in remaining), (
        f"a never-created id unexpectedly appeared in ListOutpostResolvers: {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
