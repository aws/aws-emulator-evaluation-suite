"""delete-project-absent-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-project-absent-is-idempotent"
GROUP = 'lifecycle'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteProject on a name that never existed succeeds with an empty body, twice, and BatchGetProjects
    reports the name in projectsNotFound before, between and after."""
    cb = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-behav-missing-proj-")

    pre = cb.batch_get_projects(names=[name])
    assert name in pre.get("projectsNotFound", []), pre

    first = cb.delete_project(name=name)
    extra_first = {k: v for k, v in first.items() if k != "ResponseMetadata"}
    assert extra_first == {}, first

    mid = cb.batch_get_projects(names=[name])
    assert name in mid.get("projectsNotFound", []), mid
    assert name not in {p["name"] for p in mid.get("projects", [])}, mid

    # The idempotency claim: repeating the call on the same still-absent name must
    # also succeed, not diverge into a not-found error on the "second" delete.
    second = cb.delete_project(name=name)
    extra_second = {k: v for k, v in second.items() if k != "ResponseMetadata"}
    assert extra_second == {}, second

    post = cb.batch_get_projects(names=[name])
    assert name in post.get("projectsNotFound", []), post
    assert name not in {p["name"] for p in post.get("projects", [])}, post


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
