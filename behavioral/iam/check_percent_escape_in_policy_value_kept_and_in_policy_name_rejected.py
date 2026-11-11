"""percent-escape-in-policy-value-kept-and-in-policy-name-rejected."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "percent-escape-in-policy-value-kept-and-in-policy-name-rejected"
GROUP = "policy_document_encoding"
SERVICES = ["iam"]

ESCAPED = "a%2Fb"
ESCAPED_PERCENT = "c%25d"

TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": ESCAPED}},
            }
        ],
    }
)

PERMISSIONS_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::sim2real-doc",
                "Condition": {"StringLike": {"s3:prefix": [ESCAPED, ESCAPED_PERCENT]}},
            }
        ],
    }
)

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises unless the resource is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """``(code, message)`` of a refused call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _raw_element(client, operation: str, element: str, call):
    """``(wire text of the one element, parsed response)`` for ``call``, before botocore decodes it."""
    captured: list[str] = []

    def _capture(http_response=None, **_kwargs):
        for node in ET.fromstring(http_response.content).iter():
            if node.tag.rsplit("}", 1)[-1] == element:
                captured.append(node.text or "")

    event = f"after-call.iam.{operation}"
    client.meta.events.register(event, _capture)
    try:
        parsed = call()
    finally:
        client.meta.events.unregister(event, _capture)
    assert len(captured) == 1, f"{operation}: expected one <{element}>, got {len(captured)}"
    return captured[0], parsed


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A literal %2F or %25 inside a policy value is percent-encoded again on the wire and survives one
    URL-decode unchanged, while the same escape in a policy name is refused and stores nothing."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=TRUST_POLICY, Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity"))

    iam.put_role_policy(RoleName=role, PolicyName="sim2real-inline", PolicyDocument=PERMISSIONS_POLICY)
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-inline"), "NoSuchEntity"
    ))

    raw, parsed = _raw_element(
        iam, "GetRolePolicy", "PolicyDocument",
        lambda: iam.get_role_policy(RoleName=role, PolicyName="sim2real-inline"),
    )
    assert "%252F" in raw and "%2525" in raw, (
        f"GetRolePolicy: a literal %2F / %25 must be encoded again as %252F / %2525, got {raw!r}"
    )
    values = json.loads(unquote(raw))["Statement"][0]["Condition"]["StringLike"]["s3:prefix"]
    assert values == [ESCAPED, ESCAPED_PERCENT], (
        f"GetRolePolicy: one URL-decode must give back {[ESCAPED, ESCAPED_PERCENT]!r}, got {values!r}"
    )
    sdk_values = parsed["PolicyDocument"]["Statement"][0]["Condition"]["StringLike"]["s3:prefix"]
    assert sdk_values == [ESCAPED, ESCAPED_PERCENT], (
        f"GetRolePolicy: the decoded document must keep {[ESCAPED, ESCAPED_PERCENT]!r}, got {sdk_values!r}"
    )

    raw, parsed = _raw_element(
        iam, "GetRole", "AssumeRolePolicyDocument", lambda: iam.get_role(RoleName=role)
    )
    assert "%252F" in raw, f"GetRole: a literal %2F must be encoded again as %252F, got {raw!r}"
    external_id = json.loads(unquote(raw))["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"]
    assert external_id == ESCAPED, f"GetRole: one URL-decode must give back {ESCAPED!r}, got {external_id!r}"
    sdk_external_id = (
        parsed["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"]
    )
    assert sdk_external_id == ESCAPED, (
        f"GetRole: the decoded trust policy must keep {ESCAPED!r}, got {sdk_external_id!r}"
    )

    code, message = _error(
        lambda: iam.put_role_policy(
            RoleName=role, PolicyName=ESCAPED, PolicyDocument=PERMISSIONS_POLICY
        )
    )
    assert code == "ValidationError", f"a '%' in a policy name must be refused ValidationError, got {code!r}"
    expected = (
        "The specified value for policyName is invalid. It must contain only alphanumeric "
        "characters and/or the following: +=,.@_-"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    names = iam.list_role_policies(RoleName=role)["PolicyNames"]
    assert names == ["sim2real-inline"], f"a refused PutRolePolicy must store nothing, got {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
