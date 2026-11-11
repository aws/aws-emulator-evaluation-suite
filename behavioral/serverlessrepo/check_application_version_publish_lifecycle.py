"""application-version-publish-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-version-publish-lifecycle"
GROUP = 'versions'
SERVICES = ['serverlessrepo']

# A parameterised SAM template. SAR derives ParameterDefinitions and RequiredCapabilities from
# the template it is handed, so the two templates below differ in exactly one respect: this one
# creates no IAM, the next one does.
_SQS_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Parameters:
  QueueVisibility:
    Type: Number
    Default: 30
Resources:
  Q:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !Ref QueueVisibility
Outputs:
  QueueUrl:
    Value: !Ref Q
"""

_IAM_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
"""

# ===== helpers =====


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _all_versions(sar, app_id):
    """Every SemanticVersion for app_id, paginated.

    A single-page read is not a bound on the result set, even though this listing is scoped to
    one application.
    """
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


# SAR's READ path is eventually consistent while its write path is not: CreateApplication and
# CreateApplicationVersion return the new version's metadata synchronously, but GetApplication
# omitted the Version block — and ListApplicationVersions omitted the version — for several seconds
# afterwards. Asserting on the first response makes a check a race against SAR's replication rather
# than a test of its semantics, so every read-back below polls to the expected state and fails with
# what it last saw.
_CONSISTENCY_BUDGET_S = 120.0


def _await_latest(sar, app_id, semantic_version):
    """GetApplication's Version block once the latest-version pointer reaches semantic_version."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    seen = None
    while time.time() < deadline:
        got = sar.get_application(ApplicationId=app_id)
        seen = got.get("Version", {}).get("SemanticVersion")
        if seen == semantic_version:
            return got["Version"]
        time.sleep(2)
    raise AssertionError(
        f"GetApplication's latest-version pointer never reached {semantic_version!r} within "
        f"{_CONSISTENCY_BUDGET_S}s (last saw {seen!r}); the pointer must follow the newest publish"
    )


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
    """Poll ListApplicationVersions until it lists exactly the expected set."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    listed = None
    while time.time() < deadline:
        listed = sorted(_all_versions(sar, app_id))
        if listed == sorted(expected):
            return listed
        time.sleep(2)
    raise AssertionError(
        f"ListApplicationVersions settled on {listed!r} for {app_id}, expected "
        f"{sorted(expected)!r}"
    )


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """Publishing versions advances GetApplication's latest-version pointer, an application created
    without a SemanticVersion has no versions, and each version's parameters and
    RequiredCapabilities are derived from that version's own template."""
    sar = ctx.client("serverlessrepo")
    name = ctx.unique_name("sim2real-behav-sar-")

    created = sar.create_application(
        Name=name, Author="sim2real behav", Description="version publish lifecycle",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    assert app_id.endswith(f":applications/{name}"), (
        f"ApplicationId {app_id!r} does not end in ':applications/{name}' — SAR derives the "
        f"application ARN from the requested name"
    )
    assert "Version" not in created, (
        f"CreateApplication without a SemanticVersion returned a Version block "
        f"{created.get('Version')!r}; a versionless application has none"
    )
    assert _all_versions(sar, app_id) == [], (
        f"a freshly created application already had versions {_all_versions(sar, app_id)!r}"
    )

    first = sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.0.0", TemplateBody=_SQS_TEMPLATE,
    )
    assert first["ResourcesSupported"] is True, (
        f"1.0.0 reported ResourcesSupported {first['ResourcesSupported']!r}, expected True"
    )
    assert first["RequiredCapabilities"] == [], (
        f"a template creating only an SQS queue required capabilities "
        f"{first['RequiredCapabilities']!r}, expected none"
    )
    assert first["ParameterDefinitions"] == [
        {"Name": "QueueVisibility", "DefaultValue": "30", "Type": "Number",
         "ReferencedByResources": ["Q"]}
    ], (
        f"SAR derived ParameterDefinitions {first['ParameterDefinitions']!r}; expected one "
        f"Number parameter QueueVisibility defaulting to '30' and referenced by resource Q"
    )

    second = sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.1.0", TemplateBody=_IAM_TEMPLATE,
    )
    assert second["RequiredCapabilities"] == ["CAPABILITY_IAM"], (
        f"a template creating an IAM role required capabilities "
        f"{second['RequiredCapabilities']!r}, expected ['CAPABILITY_IAM'] — the requirement is "
        f"derived per version from that version's template"
    )
    assert second["ParameterDefinitions"] == [], (
        f"the IAM template declares no parameters but SAR reported "
        f"{second['ParameterDefinitions']!r}"
    )

    _await_versions(sar, app_id, {"1.0.0", "1.1.0"})

    latest = _await_latest(sar, app_id, "1.1.0")
    assert latest["RequiredCapabilities"] == ["CAPABILITY_IAM"], (
        f"the latest-version block reported capabilities "
        f"{latest['RequiredCapabilities']!r}, expected the 1.1.0 template's ['CAPABILITY_IAM'] "
        f"rather than 1.0.0's empty list"
    )
    assert latest["ParameterDefinitions"] == [], (
        f"the latest-version block reported ParameterDefinitions "
        f"{latest['ParameterDefinitions']!r}; 1.1.0's template declares none, so the pointer is "
        f"still serving 1.0.0's derivation"
    )

    pinned = _await_version(sar, app_id, "1.0.0")
    assert pinned["RequiredCapabilities"] == [], (
        f"reading version 1.0.0 explicitly reported capabilities "
        f"{pinned['RequiredCapabilities']!r} — publishing 1.1.0 must not rewrite an "
        f"already-published version's derived metadata"
    )
    assert pinned["ParameterDefinitions"] == first["ParameterDefinitions"], (
        f"version 1.0.0 now reports ParameterDefinitions {pinned['ParameterDefinitions']!r}, but "
        f"its publish returned {first['ParameterDefinitions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
