"""device-pool-survives-parent-project-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-pool-survives-parent-project-deletion"
GROUP = 'referential-integrity'
SERVICES = ['devicefarm']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteProject on a project with a live device pool still succeeds, and the pool is
    orphaned rather than cascade-deleted: it stays readable by its own ARN after its parent
    project is gone and not found.
    """
    df = ctx.client("devicefarm")
    project_name = ctx.unique_name("sim2real-behav-df-cascade-project-")
    project_arn = df.create_project(name=project_name)["project"]["arn"]
    ctx.on_cleanup(_teardown(lambda: df.delete_project(arn=project_arn), "NotFoundException"))

    pool_name = ctx.unique_name("sim2real-behav-df-cascade-pool-")
    pool_arn = df.create_device_pool(
        projectArn=project_arn, name=pool_name,
        rules=[{"attribute": "PLATFORM", "operator": "EQUALS", "value": '"ANDROID"'}],
    )["devicePool"]["arn"]
    ctx.on_cleanup(_teardown(lambda: df.delete_device_pool(arn=pool_arn), "NotFoundException"))

    # Delete the project while the pool still exists; Device Farm does not block on it.
    df.delete_project(arn=project_arn)

    code, message = _error(lambda: df.get_project(arn=project_arn))
    assert code == "NotFoundException", f"expected NotFoundException for the deleted project, got {code}"
    expected_message = f"No project was found for arn {project_arn}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # The pool is not cascade-deleted: an independent read of it still succeeds afterward.
    pool = df.get_device_pool(arn=pool_arn)["devicePool"]
    assert pool["arn"] == pool_arn, f"expected {pool_arn!r}, got {pool['arn']!r}"
    assert pool["name"] == pool_name, f"expected {pool_name!r}, got {pool['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
