"""extension-association-drives-list-visibility."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-association-drives-list-visibility"
GROUP = "e2e"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-association-visibility"}
_SNS_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExtension -> associate it with an application -> update the
    association's parameters -> ListExtensionAssociations/ListExtensions
    reflect the change end-to-end before teardown."""
    appconfig = ctx.client("appconfig")
    sns = ctx.client("sns")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    app_id = _create_application(ctx)
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"), Tags=_SNS_TAGS
    )["TopicArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: sns.delete_topic(TopicArn=topic_arn)))

    extension_name = ctx.unique_name("sim2real-behav-ext-")
    extension = appconfig.create_extension(
        Name=extension_name,
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {"Name": "notify", "Uri": topic_arn},
            ]
        },
        Parameters={"greeting": {"Description": "greeting to send", "Required": True}},
        Tags=_TAGS,
    )
    extension_id = extension["Id"]
    ctx.on_cleanup(
        lambda: _safe_call(lambda: appconfig.delete_extension(ExtensionIdentifier=extension_id))
    )

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=extension_id,
        ResourceIdentifier=app_arn,
        Parameters={"greeting": "hello"},
        Tags=_TAGS,
    )
    assoc_id = assoc["Id"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
        )
    )
    assert assoc["Parameters"] == {"greeting": "hello"}

    # the newly created association must be visible via the list operation
    def _assoc_listed_with(expected_greeting: str) -> bool:
        items = appconfig.list_extension_associations(ResourceIdentifier=app_arn)["Items"]
        for item in items:
            if item["Id"] == assoc_id:
                full = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
                return full["Parameters"].get("greeting") == expected_greeting
        return False

    _poll_until(
        lambda: _assoc_listed_with("hello"),
        timeout_s=30.0,
        description="extension association visible in ListExtensionAssociations with initial parameters",
    )

    # the extension itself must be visible via ListExtensions
    def _extension_listed() -> bool:
        items = appconfig.list_extensions(Name=extension_name)["Items"]
        return any(item["Id"] == extension_id for item in items)

    _poll_until(_extension_listed, timeout_s=30.0, description="extension visible in ListExtensions")

    appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id, Parameters={"greeting": "updated"}
    )

    _poll_until(
        lambda: _assoc_listed_with("updated"),
        timeout_s=30.0,
        description="updated extension association parameters visible end-to-end",
    )


def _poll_until(probe, *, timeout_s: float = 30.0, interval_s: float = 1.0, description: str) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last value: {last!r}")


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFound", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
