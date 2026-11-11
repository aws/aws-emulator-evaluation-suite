"""create-data-automation-library-duplicate-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-automation-library-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second library with an existing libraryName is refused with ConflictException and the exact
    message and leaves the original unchanged and ACTIVE; another name succeeds, and after the
    original is deleted its name can be created again.
    """
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-lib-dup")
    tag_list = [{"key": "sim2real-check", "value": CHECK}]

    original_arn = bda.create_data_automation_library(
        libraryName=name, libraryDescription="original", tags=tag_list
    )["libraryArn"]
    original_cleaned_up = False

    def _cleanup_original():
        if not original_cleaned_up:
            bda.delete_data_automation_library(libraryArn=original_arn)

    ctx.on_cleanup(_cleanup_original)

    code, message = _client_error(
        lambda: bda.create_data_automation_library(libraryName=name, libraryDescription="conflicting")
    )
    assert code == "ConflictException", f"expected ConflictException on duplicate name, got {code!r} ({message})"
    assert message == "A library with this name already exists. Please choose a different name.", (
        f"unexpected message: {message!r}"
    )

    # Effect absent: the original Library's description was not overwritten by the rejected attempt.
    unchanged = bda.get_data_automation_library(libraryArn=original_arn)["library"]
    assert unchanged["libraryDescription"] == "original", (
        f"expected description 'original' to survive the rejected duplicate create, got "
        f"{unchanged['libraryDescription']!r}"
    )
    assert unchanged["status"] == "ACTIVE", f"expected original library ACTIVE, got {unchanged['status']!r}"

    # Positive control: a create with a distinct name succeeds normally.
    other_name = ctx.unique_name("sim2real-bda-lib-dup-other")
    other_arn = bda.create_data_automation_library(libraryName=other_name, tags=tag_list)["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=other_arn))
    other_fetched_name = bda.get_data_automation_library(libraryArn=other_arn)["library"]["libraryName"]
    assert other_fetched_name == other_name, f"expected libraryName {other_name!r}, got {other_fetched_name!r}"

    # Restore leg: delete the original, then the identical (freed) name succeeds. Delete is
    # asynchronous (the model has a DELETING status), so the name may stay reserved briefly —
    # retry on ConflictException up to a bounded deadline rather than assuming instant release.
    bda.delete_data_automation_library(libraryArn=original_arn)
    original_cleaned_up = True
    restored_arn = _retry_on_conflict(
        lambda: bda.create_data_automation_library(libraryName=name, libraryDescription="restored")[
            "libraryArn"
        ],
        deadline_s=60.0,
    )
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=restored_arn))
    restored = bda.get_data_automation_library(libraryArn=restored_arn)["library"]
    assert restored["libraryName"] == name, f"expected restored libraryName {name!r}, got {restored['libraryName']!r}"
    assert restored["status"] == "ACTIVE", f"expected restored library ACTIVE, got {restored['status']!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _retry_on_conflict(fn, deadline_s: float):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
