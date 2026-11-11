"""sdi-source-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sdi-source-lifecycle-crud"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSdiSource/UpdateSdiSource/DeleteSdiSource round-trip name/mode/type metadata, and a
    mutation on the deleted id fails too."""
    medialive = ctx.client("medialive")
    name = ctx.unique_name("sim2real-medialive-sdi-")
    created = medialive.create_sdi_source(
        Name=name,
        Type="SINGLE",
        Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"},
    )["SdiSource"]
    source_id = created["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_sdi_source(SdiSourceId=source_id)))
    assert created["Name"] == name, f"expected created Name {name!r}, got {created['Name']!r}"
    assert created["Type"] == "SINGLE", f"expected created Type SINGLE, got {created['Type']!r}"
    assert created["State"] == "IDLE", f"expected created State IDLE, got {created['State']!r}"

    new_name = name + "-renamed"
    medialive.update_sdi_source(SdiSourceId=source_id, Name=new_name, Type="QUAD", Mode="QUADRANT")
    described = medialive.describe_sdi_source(SdiSourceId=source_id)["SdiSource"]
    assert described["Name"] == new_name, (
        f"expected Name {new_name!r} after update, got {described['Name']!r}"
    )
    assert described["Type"] == "QUAD", f"expected Type QUAD after update, got {described['Type']!r}"
    assert described["Mode"] == "QUADRANT", (
        f"expected Mode QUADRANT after update, got {described['Mode']!r}"
    )

    medialive.delete_sdi_source(SdiSourceId=source_id)
    final = _wait_for_deleted(ctx, lambda: medialive.describe_sdi_source(SdiSourceId=source_id))
    assert final == "DELETED", (
        f"expected an independent DescribeSdiSource to settle into the terminal DELETED state, "
        f"got {final!r}"
    )

    mutate_code, mutate_message = _client_error(
        lambda: medialive.update_sdi_source(SdiSourceId=source_id, Name=new_name + "-2"),
        "UpdateSdiSource on a deleted source",
    )
    assert mutate_code == "NotFoundException", (
        f"expected UpdateSdiSource on the deleted id to fail NotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == f"SdiSource {source_id} already deleted", mutate_message


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _wait_for_deleted(ctx, describe_fn, timeout_s=120.0, interval_s=5.0):
    """Poll until the resource either 404s or settles into a terminal DELETED state."""
    from botocore.exceptions import ClientError
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = describe_fn()
            sdi = resp.get("SdiSource", resp)
            last = sdi.get("State")
            if last == "DELETED":
                return "DELETED"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return "NotFoundException"
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"resource never reached a deleted terminal state within {timeout_s}s, last={last!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
