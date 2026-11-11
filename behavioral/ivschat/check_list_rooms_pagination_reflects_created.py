"""list-rooms-pagination-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-rooms-pagination-reflects-created"
GROUP = "state"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRooms with a small maxResults paginates via nextToken, and the union of pages
    contains every room just created (filtered by our unique name prefix) exactly once."""
    ivschat = ctx.client("ivschat")
    prefix = ctx.unique_name("sim2real-ivschat-lp")
    created_arns = []
    for i in range(3):
        resp = ivschat.create_room(name=f"{prefix}-{i}", tags={"sim2real": CHECK})
        created_arns.append(resp["arn"])
        ctx.on_cleanup(lambda arn=resp["arn"]: ivschat.delete_room(identifier=arn))

    seen_arns = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = ivschat.list_rooms(**kwargs)
        for room in page.get("rooms", []):
            if room["arn"] in created_arns:
                seen_arns.add(room["arn"])
        pages += 1
        next_token = page.get("nextToken")
        if not next_token or pages > 200:
            break

    assert seen_arns == set(created_arns), f"expected {created_arns}, saw {sorted(seen_arns)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
