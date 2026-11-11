"""config-name-invalid-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "config-name-invalid-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected rejection but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfig rejects a name containing characters outside the SafeName pattern
    (`[ a-zA-Z0-9_:-]{1,256}`), while an otherwise-identical valid name succeeds."""
    gs = ctx.client("groundstation")

    good_name = ctx.unique_name("sim2real-gs-goodname-")
    good = gs.create_config(
        name=good_name,
        configData={"trackingConfig": {"autotrack": "REMOVED"}},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=good["configId"], configType=good["configType"])
    )
    assert good["configType"] == "tracking", (
        f'expected configType "tracking" for the positive control, got {good["configType"]!r}'
    )

    bad_name = ctx.unique_name("sim2real-gs-bad") + "!!invalid/name??"

    refused = _error(
        lambda: gs.create_config(
            name=bad_name,
            configData={"trackingConfig": {"autotrack": "REMOVED"}},
        )
    )
    assert refused == ("BadRequestException", "Invalid request body"), (
        f"unexpected outcome for invalid-pattern name: {refused!r}"
    )

    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_configs(**kwargs)
        for entry in page.get("configList", []):
            assert entry["name"] != bad_name, (
                f'the rejected name {bad_name!r} is visible in ListConfigs as {entry!r}'
            )
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
