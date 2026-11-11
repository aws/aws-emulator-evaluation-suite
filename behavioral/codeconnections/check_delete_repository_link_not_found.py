"""delete-repository-link-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-repository-link-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRepositoryLink on a nonexistent RepositoryLinkId returns 200, and ListRepositoryLinks
    succeeds without that id."""
    cc = ctx.client("codeconnections")
    bogus_id = str(uuid.uuid4())

    resp = cc.delete_repository_link(RepositoryLinkId=bogus_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected idempotent no-op returning 200, got {status}"

    # positive control: the API itself is otherwise functional and the bogus id is absent
    resp = cc.list_repository_links()
    assert "RepositoryLinks" in resp, f"expected RepositoryLinks key, got keys {list(resp.keys())}"
    assert not any(link["RepositoryLinkId"] == bogus_id for link in resp["RepositoryLinks"]), (
        f"bogus id {bogus_id} unexpectedly present in ListRepositoryLinks"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
