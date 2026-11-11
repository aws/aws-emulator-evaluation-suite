"""rejects-duplicate-semantic-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-duplicate-semantic-version"
GROUP = 'versions'
SERVICES = ['serverlessrepo']

_ONE_QUEUE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Q:
    Type: AWS::SQS::Queue
"""

# Different CONTENT under the same version, to establish that the conflict is on the version
# identity rather than on republishing identical bytes.
_TWO_QUEUES = _ONE_QUEUE + """  Q2:
    Type: AWS::SQS::Queue
"""


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises.

    Raises on SUCCESS rather than returning a falsy sentinel: a target that lets a published version
    be overwritten is the strongest signal this check can produce.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the republish succeeded; real AWS answers it with a conflict")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _versions(sar, app_id):
    """Every SemanticVersion for app_id, paginated."""
    out = []
    token = None
    while True:
        kwargs = {"ApplicationId": app_id, "MaxItems": 100}
        if token:
            kwargs["NextToken"] = token
        page = sar.list_application_versions(**kwargs)
        out.extend(v["SemanticVersion"] for v in page.get("Versions", []))
        token = page.get("NextToken")
        if not token:
            return out


# SAR's read path is eventually consistent while its write path is not: a publish returns the new
# version's metadata synchronously, but GetApplication and ListApplicationVersions can take several
# seconds to serve it. Poll to the expected state rather than asserting on the first response.
_CONSISTENCY_BUDGET_S = 120.0


def _await_version(sar, app_id, semantic_version):
    """The Version block of one specific published version, once SAR serves it."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    last = None
    while time.time() < deadline:
        try:
            got = sar.get_application(ApplicationId=app_id, SemanticVersion=semantic_version)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
            last = "NotFoundException"
        else:
            if "Version" in got:
                return got["Version"]
            last = sorted(got)
        time.sleep(2)
    raise AssertionError(
        f"GetApplication never served version {semantic_version!r} of {app_id} within "
        f"{_CONSISTENCY_BUDGET_S}s (last saw {last!r})"
    )


def _await_versions(sar, app_id, expected):
    """Poll ListApplicationVersions until it lists exactly the expected set of versions."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    listed = None
    while time.time() < deadline:
        listed = sorted(_versions(sar, app_id))
        if listed == sorted(expected):
            return listed
        time.sleep(2)
    raise AssertionError(
        f"ListApplicationVersions settled on {listed!r} for {app_id}, expected "
        f"{sorted(expected)!r}"
    )


def _await_latest(sar, app_id, semantic_version):
    """Poll GetApplication until its latest-version pointer reaches semantic_version."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    seen = None
    while time.time() < deadline:
        seen = sar.get_application(ApplicationId=app_id).get("Version", {}).get("SemanticVersion")
        if seen == semantic_version:
            return seen
        time.sleep(2)
    raise AssertionError(
        f"GetApplication's latest-version pointer settled on {seen!r}, expected the accepted "
        f"{semantic_version!r}"
    )


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """Republishing a taken SemanticVersion with different content is refused with ConflictException and
    its exact message, leaving the original version's CreationTime and parameters intact; 1.0.1 still
    publishes, the version list is exactly both, and the latest pointer follows 1.0.1."""
    sar = ctx.client("serverlessrepo")
    name = ctx.unique_name("sim2real-behav-sar-")

    app_id = sar.create_application(
        Name=name, Author="sim2real behav", Description="duplicate semantic version",
        SemanticVersion="1.0.0", TemplateBody=_ONE_QUEUE,
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    original = _await_version(sar, app_id, "1.0.0")
    assert original["SemanticVersion"] == "1.0.0", (
        f"the application under test reports version {original['SemanticVersion']!r} where 1.0.0 "
        f"was published"
    )

    # The conflict, with DIFFERENT content: the version identity is what is taken, not the bytes.
    code, message = _error(lambda: sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.0.0", TemplateBody=_TWO_QUEUES,
    ))
    assert code == "ConflictException", (
        f"republishing an existing SemanticVersion returned {code!r}, expected ConflictException"
    )
    expected = (
        f"Cannot publish version 1.0.0 for application {app_id} because it already exists"
    )
    assert message == expected, (
        f"republishing 1.0.0 was refused with {message!r}, expected {expected!r}"
    )

    after = _await_version(sar, app_id, "1.0.0")
    assert after["CreationTime"] == original["CreationTime"], (
        f"version 1.0.0 now reports CreationTime {after['CreationTime']!r}, was "
        f"{original['CreationTime']!r} — a refused republish must not touch the published version"
    )
    assert after["ParameterDefinitions"] == original["ParameterDefinitions"], (
        f"version 1.0.0's derived ParameterDefinitions changed from "
        f"{original['ParameterDefinitions']!r} to {after['ParameterDefinitions']!r} across a "
        f"refused republish"
    )

    # Positive control: the conflict is on the taken number only — a free one publishes.
    fresh = sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.0.1", TemplateBody=_TWO_QUEUES,
    )
    assert fresh["SemanticVersion"] == "1.0.1", (
        f"publishing the unused version 1.0.1 reported {fresh['SemanticVersion']!r}"
    )
    # Exactly the two that were accepted: the conflicting republish added nothing.
    _await_versions(sar, app_id, {"1.0.0", "1.0.1"})

    # And the newest-publish pointer followed the accepted version, not the refused one.
    _await_latest(sar, app_id, "1.0.1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
