"""rejects-template-without-transform."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-template-without-transform"
GROUP = 'versions'
SERVICES = ['serverlessrepo']

# The two templates differ in EXACTLY one line: the SAM Transform. Every other byte is shared, so a
# divergence between the two outcomes can only be attributed to that line.
_BODY = """Resources:
  Q:
    Type: AWS::SQS::Queue
"""
_WITHOUT_TRANSFORM = "AWSTemplateFormatVersion: '2010-09-09'\n" + _BODY
_WITH_TRANSFORM = ("AWSTemplateFormatVersion: '2010-09-09'\n"
                   "Transform: AWS::Serverless-2016-10-31\n" + _BODY)
# SAR echoes the parsed template back in its refusal, as the repr of the mapping it loaded.
_NO_TRANSFORM_MESSAGE = (
    "Resource with name [template] is invalid. Resource must have Transform field: "
    "OrderedDict({'AWSTemplateFormatVersion': '2010-09-09', 'Resources': "
    "OrderedDict({'Q': OrderedDict({'Type': 'AWS::SQS::Queue'})})})"
)


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises.

    Raises on SUCCESS rather than returning a falsy sentinel: a target that accepts what real AWS
    refuses is the strongest signal this check can produce, and a sentinel would disguise it as a
    mismatched error code.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call succeeded; real AWS refuses it")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


# SAR's read path is eventually consistent while its write path is not: a publish returns the new
# version's metadata synchronously, but GetApplication and ListApplicationVersions can take several
# seconds to serve it. Poll to the expected state rather than asserting on the first response.
_CONSISTENCY_BUDGET_S = 120.0


def _await_versions(sar, app_id, expected):
    """Poll ListApplicationVersions until it lists exactly the expected set of versions."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    listed = None
    while time.time() < deadline:
        listed = sorted(v["SemanticVersion"] for v in
                        sar.list_application_versions(ApplicationId=app_id,
                                                      MaxItems=100)["Versions"])
        if listed == sorted(expected):
            return listed
        time.sleep(2)
    raise AssertionError(
        f"ListApplicationVersions settled on {listed!r} for {app_id}, expected "
        f"{sorted(expected)!r}"
    )


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A template without the SAM Transform is refused with BadRequestException and its exact message on
    both the publish and the create path; the refused publish adds no version, and the refused create
    leaves no application (NotFoundException) and frees the name for a later create."""
    sar = ctx.client("serverlessrepo")

    # Positive control: the transform-bearing template is accepted, so the rejection below is
    # attributable to the missing Transform and not to the template being unusable in general.
    accepted_name = ctx.unique_name("sim2real-behav-sar-")
    app_id = sar.create_application(
        Name=accepted_name, Author="sim2real behav", Description="transform control",
        SemanticVersion="1.0.0", TemplateBody=_WITH_TRANSFORM,
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))
    _await_versions(sar, app_id, {"1.0.0"})

    # Publishing the same template minus the Transform into an application that already exists.
    code, message = _error(lambda: sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="2.0.0", TemplateBody=_WITHOUT_TRANSFORM,
    ))
    assert code == "BadRequestException", (
        f"publishing a transform-less template returned {code!r}, expected BadRequestException"
    )
    assert message == _NO_TRANSFORM_MESSAGE, (
        f"publishing a transform-less template was refused with {message!r}, expected "
        f"{_NO_TRANSFORM_MESSAGE!r}"
    )
    # The refused publish added nothing: the version set is still exactly the accepted one. (This
    # read is polled for the same reason as above, and a 2.0.0 that appeared would never settle.)
    _await_versions(sar, app_id, {"1.0.0"})

    # The same refusal on the create path, where it must leave no application at all.
    refused_name = ctx.unique_name("sim2real-behav-sar-")
    refused_id = f"{app_id.rsplit('/', 1)[0]}/{refused_name}"
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=refused_id))
    )
    code, message = _error(lambda: sar.create_application(
        Name=refused_name, Author="sim2real behav", Description="transform rejected",
        SemanticVersion="1.0.0", TemplateBody=_WITHOUT_TRANSFORM,
    ))
    assert code == "BadRequestException", (
        f"creating an application from a transform-less template returned {code!r}, expected "
        f"BadRequestException"
    )
    assert message == _NO_TRANSFORM_MESSAGE, (
        f"creating from a transform-less template was refused with {message!r}, expected "
        f"{_NO_TRANSFORM_MESSAGE!r}"
    )

    absent = _error(lambda: sar.get_application(ApplicationId=refused_id))
    assert absent[0] == "NotFoundException", (
        f"reading the application whose creation was refused returned {absent[0]!r}; the rejected "
        f"CreateApplication must leave no application behind, not an unreadable one"
    )
    expected = f"Application with id {refused_id} could not be found."
    assert absent[1] == expected, (
        f"reading the refused application answered {absent[1]!r}, expected {expected!r}"
    )

    # And the name it refused is still free: proof the rejection released it rather than reserving it.
    reused_id = sar.create_application(
        Name=refused_name, Author="sim2real behav", Description="transform rejected then reused",
        SemanticVersion="1.0.0", TemplateBody=_WITH_TRANSFORM,
    )["ApplicationId"]
    assert reused_id == refused_id, (
        f"re-creating the refused name produced {reused_id!r}, expected the same ARN "
        f"{refused_id!r} that the failed create would have taken"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
