"""sar-version-pointer-follows-latest-published-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sar-version-pointer-follows-latest-published-version"
GROUP = "application-versioning"
SERVICES = ["serverlessrepo"]

# SAR's version pointer and version list are eventually consistent after a publish.
_CONVERGE_S = 60

_SAM_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::Serverless-2016-10-31",
    "Parameters": {"QueueNameParam": {"Type": "String"}},
    "Resources": {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
        }
    },
    "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
}


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """After publishing 1.0.1, a version-less GetApplication converges on 1.0.1 while a pinned read still
    answers 1.0.0 and ListApplicationVersions lists both in order; republishing 1.0.0 is refused with
    409 ConflictException and its exact message and changes neither the pointer nor the list."""
    sar = ctx.client("serverlessrepo")

    app_name = ctx.unique_name("sim2real-behav-sarver-")
    created = sar.create_application(
        Name=app_name,
        Author="sim2real-behav",
        Description="sim2real SAR versioning check",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
        SemanticVersion="1.0.0",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: sar.delete_application(ApplicationId=app_id))
    assert created["Version"]["SemanticVersion"] == "1.0.0", (
        f"first publish reports {created['Version']['SemanticVersion']!r}"
    )

    _await_pointer(sar, app_id, "1.0.0")

    published = sar.create_application_version(
        ApplicationId=app_id,
        SemanticVersion="1.0.1",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
    )
    assert published["SemanticVersion"] == "1.0.1", (
        f"second publish reports {published['SemanticVersion']!r}"
    )
    assert published["ApplicationId"] == app_id, (
        f"second publish belongs to {published['ApplicationId']!r}"
    )

    # The pointer moved, and the older version is still individually addressable.
    _await_pointer(sar, app_id, "1.0.1")
    pinned = sar.get_application(ApplicationId=app_id, SemanticVersion="1.0.0")["Version"]
    assert pinned["SemanticVersion"] == "1.0.0", (
        f"pinned read answered with {pinned['SemanticVersion']!r}"
    )

    listed = _await_versions(sar, app_id, ["1.0.0", "1.0.1"])
    assert all(v["ApplicationId"] == app_id for v in listed), (
        f"a listed version names another application: {listed!r}"
    )
    assert listed[0]["CreationTime"] <= listed[1]["CreationTime"], (
        f"versions are not listed in publication order: {listed!r}"
    )

    # ---- a published version is immutable
    try:
        sar.create_application_version(
            ApplicationId=app_id,
            SemanticVersion="1.0.0",
            TemplateBody=json.dumps(_SAM_TEMPLATE),
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        message = exc.response["Error"]["Message"]
    else:
        raise AssertionError("re-publishing the existing version 1.0.0 succeeded")

    assert code == "ConflictException", f"re-publish code is {code!r}, expected ConflictException"
    assert status == 409, f"re-publish status is {status!r}, expected 409"
    expected = (
        f"Cannot publish version 1.0.0 for application {app_id} because it already exists"
    )
    assert message == expected, f"re-publish refusal is {message!r}, expected {expected!r}"

    # The refusal changed nothing: same pointer, same two versions.
    after = sar.get_application(ApplicationId=app_id)["Version"]["SemanticVersion"]
    assert after == "1.0.1", f"pointer is {after!r} after the rejected re-publish"
    after_listed = [
        v["SemanticVersion"]
        for v in sar.list_application_versions(ApplicationId=app_id)["Versions"]
    ]
    assert after_listed == ["1.0.0", "1.0.1"], (
        f"version list is {after_listed!r} after the rejected re-publish"
    )


def _await_pointer(sar, app_id: str, expected: str) -> None:
    """The implicit current-version pointer, converged. A version-less GetApplication answers
    without a `Version` member at all for a moment after a publish."""
    deadline = time.time() + _CONVERGE_S
    seen: object = "<no Version member>"
    while time.time() < deadline:
        got = sar.get_application(ApplicationId=app_id)
        if "Version" in got:
            seen = got["Version"]["SemanticVersion"]
            if seen == expected:
                return
        time.sleep(3)
    raise AssertionError(
        f"pointer for {app_id!r} is {seen!r} after {_CONVERGE_S}s, expected {expected!r}"
    )


def _await_versions(sar, app_id: str, expected: list[str]) -> list[dict]:
    deadline = time.time() + _CONVERGE_S
    listed: list[dict] = []
    while time.time() < deadline:
        listed = sar.list_application_versions(ApplicationId=app_id)["Versions"]
        if [v["SemanticVersion"] for v in listed] == expected:
            return listed
        time.sleep(3)
    raise AssertionError(
        f"version list is {[v['SemanticVersion'] for v in listed]!r} after {_CONVERGE_S}s, "
        f"expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
