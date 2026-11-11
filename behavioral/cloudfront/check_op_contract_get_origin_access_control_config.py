"""op-contract-get-origin-access-control-config."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-origin-access-control-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOriginAccessControlConfig returns the raw OriginAccessControlConfig and 404s on an unknown Id."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-oacc-")
    create_resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real behavioral check OAC",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = create_resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_origin_access_control(Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
    )

    # success path
    got = cf.get_origin_access_control_config(Id=oac_id)
    config = got["OriginAccessControlConfig"]
    assert config["Name"] == name, f"expected Name {name!r}, got {config.get('Name')!r}"
    assert config["SigningProtocol"] == "sigv4", (
        f"expected SigningProtocol 'sigv4', got {config.get('SigningProtocol')!r}"
    )
    assert config["SigningBehavior"] == "always", (
        f"expected SigningBehavior 'always', got {config.get('SigningBehavior')!r}"
    )
    assert config["OriginAccessControlOriginType"] == "s3", (
        f"expected OriginAccessControlOriginType 's3', got {config.get('OriginAccessControlOriginType')!r}"
    )
    assert got["ETag"], "GetOriginAccessControlConfig must return an ETag"

    # error boundary: unknown OAC Id
    err, message = _error(lambda: cf.get_origin_access_control_config(Id="OACCBOGUS0000000000"))
    assert err == "NoSuchOriginAccessControl", f"expected NoSuchOriginAccessControl, got {err}"
    assert message == "The specified origin access control does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
