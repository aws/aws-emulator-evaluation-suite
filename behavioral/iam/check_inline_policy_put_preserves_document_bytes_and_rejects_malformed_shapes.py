"""inline-policy-put-preserves-document-bytes-and-rejects-malformed-shapes."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inline-policy-put-preserves-document-bytes-and-rejects-malformed-shapes"
GROUP = "policy_document_validation"
SERVICES = ["iam"]

TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# Deliberately unusual key order and inner spacing, so the byte-exact comparison below is a
# real test of what AWS stores rather than an accident of a canonical serialization both the
# check and the target happen to produce.
VALID_DOCUMENT = (
    '{"Statement": [{"Resource": "*", "Action": "s3:ListBucket", "Effect": "Allow"}], '
    '"Version": "2012-10-17"}'
)

STATEMENT_WRONG_TYPE = json.dumps({"Version": "2012-10-17", "Statement": "nope"})

INVALID_EFFECT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Maybe", "Action": "iam:GetUser", "Resource": "*"}],
    }
)

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _error(fn):
    """``(code, message)`` of a call real AWS refuses. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _raw_policy_document(client, event_name: str, call) -> str:
    """The wire-level ``PolicyDocument`` text ``call`` returns, XML entities unescaped, captured
    before botocore's own percent-decode-and-parse handler turns it into a dict."""
    captured: dict = {}

    def _capture(http_response=None, **kwargs):
        for element in ET.fromstring(http_response.content).iter():
            if element.tag.rsplit("}", 1)[-1] == "PolicyDocument":
                captured["raw"] = element.text or ""
                return

    client.meta.events.register(event_name, _capture)
    try:
        call()
    finally:
        client.meta.events.unregister(event_name, _capture)
    assert "raw" in captured, f"{event_name} response carried no <PolicyDocument> element"
    return captured["raw"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put{Role,User,Group}Policy refuses a Statement of the wrong type and an Effect outside
    Allow/Deny with MalformedPolicyDocument, storing nothing; a valid document submitted on the
    same resource round-trips through Get{Role,User,Group}Policy byte-exact after URL-decoding."""
    iam = ctx.client("iam")

    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST_POLICY, Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))

    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))

    group = ctx.unique_name("sim2real-behav-group-")
    iam.create_group(GroupName=group)  # CreateGroup takes no Tags
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))

    resources = [
        ("role", role, "RoleName", iam.put_role_policy, iam.get_role_policy,
         iam.list_role_policies, iam.delete_role_policy),
        ("user", user, "UserName", iam.put_user_policy, iam.get_user_policy,
         iam.list_user_policies, iam.delete_user_policy),
        ("group", group, "GroupName", iam.put_group_policy, iam.get_group_policy,
         iam.list_group_policies, iam.delete_group_policy),
    ]

    for kind, name, name_kwarg, put_policy, get_policy, list_policies, delete_policy in resources:
        bad_statement_name = "sim2real-bad-statement-type"
        bad_effect_name = "sim2real-bad-effect-enum"
        good_name = "sim2real-good"

        code, message = _error(
            lambda: put_policy(
                PolicyName=bad_statement_name, PolicyDocument=STATEMENT_WRONG_TYPE,
                **{name_kwarg: name},
            )
        )
        assert code == "MalformedPolicyDocument", (
            f"{kind}: a Statement that is a string, not an array, must be refused "
            f"MalformedPolicyDocument, got {code}"
        )
        assert message == "Syntax errors in policy.", (
            f"{kind}: expected the exact message 'Syntax errors in policy.', got {message!r}"
        )

        code, message = _error(
            lambda: put_policy(
                PolicyName=bad_effect_name, PolicyDocument=INVALID_EFFECT, **{name_kwarg: name}
            )
        )
        assert code == "MalformedPolicyDocument", (
            f"{kind}: an Effect outside Allow/Deny must be refused MalformedPolicyDocument, got {code}"
        )
        assert message == "Syntax errors in policy.", (
            f"{kind}: expected the exact message 'Syntax errors in policy.', got {message!r}"
        )

        for bad_name in (bad_statement_name, bad_effect_name):
            code, message = _error(
                lambda bad_name=bad_name: get_policy(PolicyName=bad_name, **{name_kwarg: name})
            )
            assert code == "NoSuchEntity", (
                f"{kind}: a refused PutPolicy must not persist; GetPolicy({bad_name!r}) gave {code}"
            )
            expected = f"The {kind} policy with name {bad_name} cannot be found."
            assert message == expected, f"{kind}: expected {expected!r}, got {message!r}"

        put_policy(PolicyName=good_name, PolicyDocument=VALID_DOCUMENT, **{name_kwarg: name})
        ctx.on_cleanup(
            lambda delete_policy=delete_policy, name_kwarg=name_kwarg, name=name, good_name=good_name: (
                delete_policy(PolicyName=good_name, **{name_kwarg: name})
            )
        )

        names = list_policies(**{name_kwarg: name})["PolicyNames"]
        assert names == [good_name], (
            f"{kind}: expected only {good_name!r} stored, got {names} — "
            "a refused PutPolicy must leave nothing behind"
        )

        event_name = f"after-call.iam.Get{kind.capitalize()}Policy"
        raw = _raw_policy_document(
            iam, event_name,
            lambda: get_policy(PolicyName=good_name, **{name_kwarg: name}),
        )
        decoded = unquote(raw)
        assert decoded == VALID_DOCUMENT, (
            f"{kind}: the stored document must round-trip byte-exact after URL-decoding; "
            f"submitted {VALID_DOCUMENT!r}, got {decoded!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
