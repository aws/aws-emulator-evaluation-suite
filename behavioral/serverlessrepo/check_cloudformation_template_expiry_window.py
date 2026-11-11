"""cloudformation-template-expiry-window."""
from __future__ import annotations

import datetime
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudformation-template-expiry-window"
GROUP = 'templates'
SERVICES = ['serverlessrepo']

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")

_SQS_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Q:
    Type: AWS::SQS::Queue
"""


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: a target that accepts
    what real AWS refuses is the strongest signal this check can produce, and a sentinel would
    disguise it as an error-code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; real AWS answers it with an error")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


# SAR's read path is eventually consistent while its write path is not: CreateApplication returns
# the published version's metadata synchronously, but GetApplication can take several seconds to
# serve it. Wait for the version to be readable before asking SAR to generate a template FROM it, or the
# generate races the replication and 404s.
_CONSISTENCY_BUDGET_S = 120.0


def _await_version(sar, app_id, semantic_version):
    """Block until SAR serves one specific published version, and return its Version block."""
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


def _parse_ts(value):
    """SAR stamps nanosecond precision ('2024-01-01T00:00:00.123456789Z'); datetime holds micros."""
    m = _TS_RE.match(value)
    assert m, f"timestamp {value!r} is not the ISO-8601 UTC form SAR returns"
    micros = (m.group(2) or "0").ljust(6, "0")[:6]
    return datetime.datetime.fromisoformat(f"{m.group(1)}.{micros}+00:00")


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A generated CloudFormation template reaches ACTIVE with a UUID TemplateId, the application id and
    version 1.0.0, and an ExpirationTime exactly six hours after its CreationTime; a well-formed
    TemplateId SAR never issued is refused with NotFoundException and its exact message."""
    sar = ctx.client("serverlessrepo")
    name = ctx.unique_name("sim2real-behav-sar-")

    app_id = sar.create_application(
        Name=name, Author="sim2real behav", Description="template expiry window",
        SemanticVersion="1.0.0", TemplateBody=_SQS_TEMPLATE,
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    _await_version(sar, app_id, "1.0.0")

    made = sar.create_cloud_formation_template(ApplicationId=app_id, SemanticVersion="1.0.0")
    template_id = made["TemplateId"]
    assert _UUID_RE.match(template_id), (
        f"CreateCloudFormationTemplate minted TemplateId {template_id!r}; the model documents a "
        f"lowercase UUID"
    )
    assert made["Status"] in ("PREPARING", "ACTIVE"), (
        f"a freshly requested template reported Status {made['Status']!r}; SAR starts it at "
        f"PREPARING and settles it at ACTIVE"
    )

    # Poll the documented transition rather than sleeping: the template is usable only at ACTIVE.
    deadline = time.time() + 120
    got = sar.get_cloud_formation_template(ApplicationId=app_id, TemplateId=template_id)
    while got["Status"] == "PREPARING" and time.time() < deadline:
        time.sleep(3)
        got = sar.get_cloud_formation_template(ApplicationId=app_id, TemplateId=template_id)
    assert got["Status"] == "ACTIVE", (
        f"template {template_id!r} reported Status {got['Status']!r} after polling to the "
        f"deadline; SAR settles a prepared template at ACTIVE"
    )

    assert got["TemplateId"] == template_id, (
        f"reading template {template_id!r} returned TemplateId {got['TemplateId']!r}"
    )
    assert got["ApplicationId"] == app_id, (
        f"the template names application {got['ApplicationId']!r}, expected {app_id!r}"
    )
    assert got["SemanticVersion"] == "1.0.0", (
        f"the template names version {got['SemanticVersion']!r}, expected the 1.0.0 it was "
        f"generated from"
    )

    window = _parse_ts(got["ExpirationTime"]) - _parse_ts(got["CreationTime"])
    assert window == datetime.timedelta(hours=6), (
        f"ExpirationTime {got['ExpirationTime']!r} is {window} after CreationTime "
        f"{got['CreationTime']!r}; SAR expires a generated template exactly 6 hours after it is "
        f"created"
    )

    # A well-formed TemplateId that SAR never issued must be refused, not answered.
    unissued = "00000000-0000-4000-8000-000000000000"
    assert unissued != template_id, "the fixed probe id collided with the minted one"
    code, message = _error(
        lambda: sar.get_cloud_formation_template(ApplicationId=app_id, TemplateId=unissued)
    )
    assert code == "NotFoundException", (
        f"reading an unissued TemplateId returned {code!r}, expected NotFoundException"
    )
    expected = f"Template with id {unissued} can not be found."
    assert message == expected, (
        f"reading an unissued TemplateId was refused with {message!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
