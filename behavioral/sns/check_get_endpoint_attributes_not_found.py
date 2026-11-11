"""get-endpoint-attributes-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-endpoint-attributes-not-found"
GROUP = 'error-semantics'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEndpointAttributes on a well-formed but nonexistent endpoint under a real platform
    application raises NotFound with "Endpoint does not exist".
    """
    sns = ctx.client("sns")

    # BAIDU accepts arbitrary key pairs (GCM/ADM reject fake credentials), and a real
    # endpoint cannot be created without a live Baidu credential, so only the app is real.
    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    control = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert control.get("Enabled") in ("true", "false"), (
        f"positive control: expected a real platform application to be readable, got {control}"
    )

    ghost = f"{app_arn.replace(':app/', ':endpoint/', 1)}/{uuid.uuid4()}"
    code, message = _error(lambda: sns.get_endpoint_attributes(EndpointArn=ghost))
    assert code == "NotFound", f"GetEndpointAttributes: expected NotFound, got {code}"
    expected = 'Endpoint does not exist'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
