"""update-extension-parameter-schema-enforced-server-side."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-extension-parameter-schema-enforced-server-side"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension enforces the documented parameter schema constraint that a
    Dynamic parameter cannot also be Required, rejecting an update that would leave
    the parameter definition in that state rather than silently accepting it."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {
                    "Name": "notify",
                    "Uri": f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default",
                }
            ]
        },
        Parameters={"P1": {"Required": False, "Dynamic": False}},
        Tags={"sim2real": CHECK},
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    def _make_dynamic_and_required():
        appconfig.update_extension(
            ExtensionIdentifier=ext_id,
            Parameters={"P1": {"Required": True, "Dynamic": True}},
        )

    code, message = _error(_make_dynamic_and_required)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "Extension parameters P1 can not be both required and dynamic"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the parameter definition kept its original (valid) state.
    unchanged = appconfig.get_extension(ExtensionIdentifier=ext_id)
    p1 = unchanged["Parameters"]["P1"]
    assert p1.get("Required", False) is False, f"expected Required False, got {p1.get('Required')!r}"
    assert p1.get("Dynamic", False) is False, f"expected Dynamic False, got {p1.get('Dynamic')!r}"

    # Positive control: marking the same parameter Required (without Dynamic) succeeds.
    appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Parameters={"P1": {"Required": True, "Dynamic": False}},
    )
    updated = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert updated["Parameters"]["P1"]["Required"] is True, (
        f"expected Required True after accepted update, got {updated['Parameters']['P1']['Required']!r}"
    )
    assert updated["Parameters"]["P1"].get("Dynamic", False) is False, (
        f"expected Dynamic False after accepted update, got {updated['Parameters']['P1'].get('Dynamic')!r}"
    )


def _error(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
