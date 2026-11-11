"""preset-update-reflects-in-get."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "preset-update-reflects-in-get"
GROUP = "state"
SERVICES = ["mediaconvert"]
NOT_FOUND_MESSAGE = "The resource you specified in name was not found."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePreset's changes (Category, Description) are durably persisted and visible on a
    subsequent GetPreset, LastUpdated advances, and DeletePreset actually removes it."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-preset-")
    settings = {
        "ContainerSettings": {"Container": "MP4"},
        "VideoDescription": {
            "CodecSettings": {
                "Codec": "H_264",
                "H264Settings": {
                    "RateControlMode": "QVBR",
                    "QvbrSettings": {"QvbrQualityLevel": 7},
                    "MaxBitrate": 5000000,
                    "SceneChangeDetect": "ENABLED",
                },
            }
        },
    }
    mc.create_preset(
        Name=name,
        Settings=settings,
        Category="cat-a",
        Description="orig",
        Tags={"sim2real-audit": "preset-update-reflects-in-get"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete(mc, name))

    before = mc.get_preset(Name=name)["Preset"]
    assert before["Category"] == "cat-a", f"expected Category cat-a, got {before['Category']!r}"
    assert before["Description"] == "orig", f"expected Description orig, got {before['Description']!r}"

    mc.update_preset(Name=name, Category="cat-b", Description="updated")
    after = mc.get_preset(Name=name)["Preset"]
    assert after["Category"] == "cat-b", f"expected Category cat-b after update, got {after['Category']!r}"
    assert after["Description"] == "updated", (
        f"expected Description updated after update, got {after['Description']!r}"
    )
    assert after["LastUpdated"] >= before["LastUpdated"], (
        f"expected LastUpdated to advance on update, before={before['LastUpdated']!r} "
        f"after={after['LastUpdated']!r}"
    )

    mc.delete_preset(Name=name)
    code, message = _error(lambda: mc.get_preset(Name=name))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(mc, name):
    from botocore.exceptions import ClientError

    try:
        mc.delete_preset(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
