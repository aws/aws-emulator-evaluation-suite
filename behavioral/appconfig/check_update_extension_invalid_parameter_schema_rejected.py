"""update-extension-invalid-parameter-schema-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-extension-invalid-parameter-schema-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-extension-invalid-parameter-schema-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension with a parameter both Dynamic and Required raises BadRequestException and
    leaves the extension unchanged; with Required=False it is applied in place, keeping the same
    VersionNumber.
    """
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = appconfig.meta.region_name
    name = ctx.unique_name("sim2real-ext-")
    created = appconfig.create_extension(
        Name=name,
        Actions={
            "ON_DEPLOYMENT_START": [
                {
                    "Name": "notify",
                    "Uri": f"arn:aws:sns:{region}:{account_id}:sim2real-fake-topic",
                }
            ]
        },
        Parameters={"topicName": {"Required": True, "Dynamic": False}},
        Tags=_TAGS,
    )
    ext_id = created["Id"]
    assert created["VersionNumber"] == 1, f"expected initial VersionNumber 1, got {created['VersionNumber']}"
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    code, message = _error(
        lambda: appconfig.update_extension(
            ExtensionIdentifier=ext_id,
            Parameters={"topicName": {"Required": True, "Dynamic": True}},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = "Extension parameters topicName can not be both required and dynamic"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert unchanged["VersionNumber"] == 1, "rejected update must not create a new version"
    assert unchanged["Parameters"]["topicName"]["Required"] is True, (
        f"expected Required to stay True after the rejected update, "
        f"got {unchanged['Parameters']['topicName']['Required']!r}"
    )
    assert unchanged["Parameters"]["topicName"]["Dynamic"] is False, (
        f"expected Dynamic to stay False after the rejected update, "
        f"got {unchanged['Parameters']['topicName']['Dynamic']!r}"
    )

    fixed = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Parameters={"topicName": {"Required": False, "Dynamic": True}},
    )
    assert fixed["VersionNumber"] == unchanged["VersionNumber"], (
        "a valid UpdateExtension call updates the extension's parameters in place, without "
        f"minting a new version (expected {unchanged['VersionNumber']}, got {fixed['VersionNumber']})"
    )
    assert fixed["Parameters"]["topicName"]["Required"] is False, (
        f"expected Required False after the accepted fix, got {fixed['Parameters']['topicName']['Required']!r}"
    )
    assert fixed["Parameters"]["topicName"]["Dynamic"] is True, (
        f"expected Dynamic True after the accepted fix, got {fixed['Parameters']['topicName']['Dynamic']!r}"
    )

    confirmed = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert confirmed["VersionNumber"] == fixed["VersionNumber"], (
        f"independent read expected VersionNumber {fixed['VersionNumber']}, got {confirmed['VersionNumber']}"
    )


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available and must not be
    reported as a plain code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected UpdateExtension to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
