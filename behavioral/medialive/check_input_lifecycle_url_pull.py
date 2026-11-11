"""input-lifecycle-url-pull."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "input-lifecycle-url-pull"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInput/UpdateInput/DeleteInput round-trip for a pull-type input, with deletion actually taking effect."""
    medialive = ctx.client("medialive")
    name = ctx.unique_name("sim2real-medialive-input-")
    created = medialive.create_input(
        Name=name,
        Type="URL_PULL",
        Sources=[{"Url": "https://d3rlna7iyyu8wu.cloudfront.net/hls/bipbop_16x9.m3u8"}],
        Tags={"sim2real-check": CHECK},
    )["Input"]
    input_id = created["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_input(InputId=input_id)))
    assert created["Name"] == name, f"expected Name={name!r}, got {created['Name']!r}"
    assert created["Type"] == "URL_PULL", f"expected Type=URL_PULL, got {created['Type']!r}"
    assert created["State"] == "DETACHED", f"expected State=DETACHED on create, got {created['State']!r}"

    described = medialive.describe_input(InputId=input_id)
    described_url = described["Sources"][0]["Url"]
    assert described_url == "https://d3rlna7iyyu8wu.cloudfront.net/hls/bipbop_16x9.m3u8", (
        f"independent describe_input read back a different source url: {described_url!r}"
    )

    new_name = name + "-renamed"
    medialive.update_input(
        InputId=input_id,
        Name=new_name,
        Sources=[{"Url": "https://d3rlna7iyyu8wu.cloudfront.net/hls/bipbop_4x3.m3u8"}],
    )
    updated = medialive.describe_input(InputId=input_id)
    assert updated["Name"] == new_name, f"expected updated Name={new_name!r}, got {updated['Name']!r}"
    updated_url = updated["Sources"][0]["Url"]
    assert updated_url == "https://d3rlna7iyyu8wu.cloudfront.net/hls/bipbop_4x3.m3u8", (
        f"independent describe_input read back a stale source url after update: {updated_url!r}"
    )

    medialive.delete_input(InputId=input_id)
    final = _wait_for_deleted(ctx, lambda: medialive.describe_input(InputId=input_id))
    assert final == "DELETED", f"expected deleted input to settle DELETED, last state was {final!r}"

    mutation_code, mutation_message = _error(lambda: medialive.update_input(InputId=input_id, Name=new_name + "-dead"))
    assert mutation_code == "NotFoundException", (
        f"expected UpdateInput on a deleted input to fail NotFoundException, got {mutation_code!r}"
    )
    assert mutation_message == f"inputId={input_id} already deleted", (
        f"unexpected NotFoundException message: {mutation_message!r}"
    )


def _error(fn):
    """Run ``fn`` and return the ``(code, message)`` of the ClientError it raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("call succeeded; expected a ClientError")


def _wait_for_deleted(ctx, describe_fn, timeout_s=120.0, interval_s=5.0):
    """Poll until the resource settles into the terminal DELETED state."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = describe_fn().get("State")
        if last == "DELETED":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"resource never reached the DELETED terminal state within {timeout_s}s, last={last!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
