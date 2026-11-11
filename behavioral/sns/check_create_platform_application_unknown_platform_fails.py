"""create-platform-application-unknown-platform-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-platform-application-unknown-platform-fails"
GROUP = 'platform-application'
SERVICES = ['sns']

def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _app_names(sns):
    names = set()
    paginator = sns.get_paginator("list_platform_applications")
    for page in paginator.paginate():
        for app in page["PlatformApplications"]:
            names.add(app["PlatformApplicationArn"].rsplit("/", 1)[-1])
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePlatformApplication with an unknown Platform is refused with InvalidParameter and
    lists nothing, while a BAIDU application in the same run is accepted and listed."""
    sns = ctx.client("sns")

    # BAIDU accepts an arbitrary API-key/secret-key pair with no live credential validation.
    ok_name = ctx.unique_name("sim2real-behav-sns-app-ok-")
    app_arn = sns.create_platform_application(
        Name=ok_name,
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))
    assert ok_name in _app_names(sns), (
        f"positive control did not register {ok_name!r} in ListPlatformApplications"
    )

    bad_name = ctx.unique_name("sim2real-behav-sns-app-bad-")
    code, message = _error(
        lambda: sns.create_platform_application(
            Name=bad_name,
            Platform="NOT_A_REAL_PLATFORM",
            Attributes={"PlatformCredential": "whatever"},
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == "Invalid parameter: Platform Reason: NOT_A_REAL_PLATFORM is not supported", (
        f"unexpected InvalidParameter message for an unknown Platform: {message!r}"
    )

    assert bad_name not in _app_names(sns), (
        f"CreatePlatformApplication was rejected but {bad_name!r} appears in "
        f"ListPlatformApplications anyway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
