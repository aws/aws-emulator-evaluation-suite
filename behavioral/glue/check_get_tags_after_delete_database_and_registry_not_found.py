"""get-tags-after-delete-database-and-registry-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'get-tags-after-delete-database-and-registry-not-found'
GROUP = 'overly-permissive'
SERVICES = ['glue']


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_entity_not_found(fn, expected_message: str, *, budget_s: float = 30.0,
                           poll_s: float = 2.0) -> None:
    """Polls ``fn`` to the terminal EntityNotFoundException carrying ``expected_message``."""
    deadline = time.monotonic() + budget_s
    last_success = None
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            assert error["Code"] == "EntityNotFoundException", (
                f"expected EntityNotFoundException, got {error['Code']!r}"
            )
            assert error["Message"] == expected_message, error["Message"]
            return
        last_success = result
        if time.monotonic() > deadline:
            raise AssertionError(
                f"still answering after {budget_s}s instead of EntityNotFoundException: {last_success!r}"
            )
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTags on a deleted database or registry's ARN raises EntityNotFoundException, naming
    the deleted resource; a sibling resource of the same kind stays taggable.
    """
    glue = ctx.client("glue")

    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"k": "v"})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))
    db_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{db_name}"
    assert glue.get_tags(ResourceArn=db_arn)["Tags"] == {"k": "v"}

    control_db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": control_db_name}, Tags={"k": "v"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=control_db_name))
    control_db_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{control_db_name}"

    glue.delete_database(Name=db_name)
    _poll_entity_not_found(
        lambda: glue.get_tags(ResourceArn=db_arn), f"Database {db_name} not found."
    )

    # Positive control: deleting one database leaves a sibling database's tags readable.
    assert glue.get_tags(ResourceArn=control_db_arn)["Tags"] == {"k": "v"}

    registry_name = ctx.unique_name("sim2real-behav-registry-")
    registry_arn = glue.create_registry(RegistryName=registry_name, Tags={"k": "v"})["RegistryArn"]
    ctx.on_cleanup(_teardown(
        lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}),
        "EntityNotFoundException",
    ))
    assert glue.get_tags(ResourceArn=registry_arn)["Tags"] == {"k": "v"}

    control_registry_name = ctx.unique_name("sim2real-behav-registry-")
    control_registry_arn = glue.create_registry(
        RegistryName=control_registry_name, Tags={"k": "v"}
    )["RegistryArn"]
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": control_registry_name}))

    glue.delete_registry(RegistryId={"RegistryName": registry_name})
    _poll_entity_not_found(
        lambda: glue.get_tags(ResourceArn=registry_arn),
        f"Registry is not found. RegistryName: null, RegistryArn: {registry_arn}",
    )

    # Positive control: deleting one registry leaves a sibling registry's tags readable.
    assert glue.get_tags(ResourceArn=control_registry_arn)["Tags"] == {"k": "v"}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
