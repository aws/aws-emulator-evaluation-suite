"""rejects-unshareable-policy-statement."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-unshareable-policy-statement"
GROUP = 'sharing'
SERVICES = ['serverlessrepo']

_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Q:
    Type: AWS::SQS::Queue
"""

# SAR's policy actions are UNPREFIXED names ("Deploy", "GetApplication"), not IAM-style
# "serverlessrepo:Deploy" strings. Nothing is ever created in the grantee account; the grant lives
# only until this check deletes the application.
_GRANTEE_CANDIDATES = ("123456789012", "111111111111", "000000000000")


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises.

    Raises on SUCCESS rather than returning a falsy sentinel: a target that accepts a statement real
    AWS refuses is the strongest signal this check can produce.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("PutApplicationPolicy succeeded; real AWS refuses this statement")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


# SAR's read path is eventually consistent, so "the policy is unchanged" has to be read as a
# CONVERGENCE on the granted statement rather than off one response — a lagging read would otherwise
# report a rejection as having wiped the policy.
_CONSISTENCY_BUDGET_S = 120.0


def _await_policy(sar, app_id, expected, what):
    """Poll GetApplicationPolicy until its statements equal expected."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    seen = None
    want = sorted(expected, key=lambda s: s["StatementId"])
    while time.time() < deadline:
        try:
            seen = sar.get_application_policy(ApplicationId=app_id)["Statements"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
            seen = "NotFoundException"  # the application itself is not readable yet
        else:
            if sorted(seen, key=lambda s: s["StatementId"]) == want:
                return seen
        time.sleep(2)
    raise AssertionError(f"{what}: the application policy settled on {seen!r}, expected {want!r}")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """PutApplicationPolicy refuses the owner as principal, an unknown action and a non-account principal
    with BadRequestException and a distinct exact message each, and every refusal leaves the granted
    control statement list unchanged."""
    sar = ctx.client("serverlessrepo")
    owner = ctx.client("sts").get_caller_identity()["Account"]
    grantees = [g for g in _GRANTEE_CANDIDATES if g != owner]
    assert grantees, (
        f"the account under test {owner!r} collides with every placeholder grantee "
        f"{_GRANTEE_CANDIDATES!r}; this check needs one id that is not the application owner"
    )
    grantee = grantees[0]

    name = ctx.unique_name("sim2real-behav-sar-")
    app_id = sar.create_application(
        Name=name, Author="sim2real behav", Description="unshareable policy statements",
        SemanticVersion="1.0.0", TemplateBody=_TEMPLATE,
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    # Positive control, in this file: a well-formed statement IS accepted, so each rejection below
    # is attributable to the one field it varies and not to sharing being unavailable.
    granted = [{"StatementId": "sim2real-behav-control", "Actions": ["Deploy"],
                "Principals": [grantee]}]
    control = sar.put_application_policy(ApplicationId=app_id, Statements=granted)["Statements"]
    assert control == [{"StatementId": "sim2real-behav-control", "Actions": ["Deploy"],
                        "Principals": [grantee], "PrincipalOrgIDs": []}], (
        f"the positive control returned {control!r}; a well-formed Deploy grant to {grantee!r} must "
        f"be accepted before any rejection can be attributed to a single varied field"
    )

    # Each entry varies exactly one field of the accepted statement above.
    rejections = [
        ("the application's own owner as principal",
         [{"Actions": ["Deploy"], "Principals": [owner]}],
         "You cannot set principal to resource owner"),
        ("an action outside SAR's vocabulary",
         [{"Actions": ["Undeploy"], "Principals": [grantee]}],
         "Action Undeploy is invalid"),
        ("a principal that is not an account id",
         [{"Actions": ["Deploy"], "Principals": ["not-an-account"]}],
         "Principal not-an-account is invalid"),
    ]
    for label, statements, expected in rejections:
        code, message = _error(
            lambda s=statements: sar.put_application_policy(ApplicationId=app_id, Statements=s)
        )
        assert code == "BadRequestException", (
            f"a policy naming {label} returned {code!r}, expected BadRequestException"
        )
        assert message == expected, (
            f"a policy naming {label} was refused with message {message!r}, expected "
            f"{expected!r}: the three refusal reasons share one code, so the message is the only "
            f"thing distinguishing them"
        )
        # A refused PutApplicationPolicy must not disturb the statement list it would have replaced.
        _await_policy(sar, app_id, control, f"after refusing a policy naming {label}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
