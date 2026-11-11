"""update-branch-fields-persist."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-branch-fields-persist"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBranch persists stage/framework/ttl changes, visible on a subsequent GetBranch."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(
        appId=app_id,
        branchName=branch_name,
        stage="DEVELOPMENT",
        framework="Web",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    amplify.update_branch(appId=app_id, branchName=branch_name, stage="BETA", framework="React", ttl="10")

    fetched = amplify.get_branch(appId=app_id, branchName=branch_name)["branch"]
    assert fetched["stage"] == "BETA", f"expected stage BETA after update_branch, got {fetched['stage']!r}"
    assert fetched["framework"] == "React", (
        f"expected framework React after update_branch, got {fetched['framework']!r}"
    )
    assert fetched["ttl"] == "10", f"expected ttl '10' after update_branch, got {fetched['ttl']!r}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
