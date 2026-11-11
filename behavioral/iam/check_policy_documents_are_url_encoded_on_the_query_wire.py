"""policy-documents-are-url-encoded-on-the-query-wire."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-documents-are-url-encoded-on-the-query-wire"
GROUP = "policy_document_encoding"
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

UPDATED_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# A space, '+', '&' and '<' in a resource exercise both the URL encoding and the XML escaping.
PERMISSIONS_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::sim2real-doc/a b+c&<d>",
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


def _raw_elements(client, operation: str, element: str, call) -> list[str]:
    """The text of every ``element`` in the XML body ``call`` returns, before botocore decodes it."""
    captured: list[str] = []

    def _capture(http_response=None, **_kwargs):
        for node in ET.fromstring(http_response.content).iter():
            if node.tag.rsplit("}", 1)[-1] == element:
                captured.append(node.text or "")

    event = f"after-call.iam.{operation}"
    client.meta.events.register(event, _capture)
    try:
        call()
    finally:
        client.meta.events.unregister(event, _capture)
    return captured


def _assert_encoded_once(where: str, raw: list[str], sent: str) -> None:
    """``raw`` holds one percent-encoded copy of ``sent`` that a single URL-decode restores."""
    assert len(raw) == 1, f"{where}: expected exactly one document element, got {len(raw)}"
    text = raw[0]
    assert "{" not in text and '"' not in text, (
        f"{where}: the document must be URL-encoded on the wire, got raw JSON {text[:120]!r}"
    )
    assert text.startswith("%7B") and "%22" in text, (
        f"{where}: expected a percent-encoded JSON object (%7B ... %22), got {text[:120]!r}"
    )
    decoded = unquote(text)
    assert json.loads(decoded) == json.loads(sent), (
        f"{where}: one URL-decode must restore the submitted document; sent {sent!r}, got {decoded!r}"
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Role trust policies, inline policies and managed policy versions come back percent-encoded
    inside the XML, and exactly one URL-decode restores the submitted JSON, across get, list and
    update."""
    iam = ctx.client("iam")
    path = f"/sim2real/{ctx.unique_name('p-')}/"

    role = ctx.unique_name("sim2real-behav-role-")
    raw = _raw_elements(
        iam, "CreateRole", "AssumeRolePolicyDocument",
        lambda: iam.create_role(
            RoleName=role, Path=path, AssumeRolePolicyDocument=TRUST_POLICY, Tags=_TAGS
        ),
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity"))
    _assert_encoded_once("CreateRole response", raw, TRUST_POLICY)

    raw = _raw_elements(
        iam, "GetRole", "AssumeRolePolicyDocument", lambda: iam.get_role(RoleName=role)
    )
    _assert_encoded_once("GetRole response", raw, TRUST_POLICY)

    raw = _raw_elements(
        iam, "ListRoles", "AssumeRolePolicyDocument", lambda: iam.list_roles(PathPrefix=path)
    )
    _assert_encoded_once("ListRoles response", raw, TRUST_POLICY)

    iam.update_assume_role_policy(RoleName=role, PolicyDocument=UPDATED_TRUST_POLICY)
    raw = _raw_elements(
        iam, "GetRole", "AssumeRolePolicyDocument", lambda: iam.get_role(RoleName=role)
    )
    _assert_encoded_once("GetRole after UpdateAssumeRolePolicy response", raw, UPDATED_TRUST_POLICY)

    iam.put_role_policy(RoleName=role, PolicyName="sim2real-inline", PolicyDocument=PERMISSIONS_POLICY)
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-inline"), "NoSuchEntity"
    ))
    raw = _raw_elements(
        iam, "GetRolePolicy", "PolicyDocument",
        lambda: iam.get_role_policy(RoleName=role, PolicyName="sim2real-inline"),
    )
    _assert_encoded_once("GetRolePolicy response", raw, PERMISSIONS_POLICY)

    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path=path, Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: iam.delete_user(UserName=user), "NoSuchEntity"))
    iam.put_user_policy(UserName=user, PolicyName="sim2real-inline", PolicyDocument=PERMISSIONS_POLICY)
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_user_policy(UserName=user, PolicyName="sim2real-inline"), "NoSuchEntity"
    ))
    raw = _raw_elements(
        iam, "GetUserPolicy", "PolicyDocument",
        lambda: iam.get_user_policy(UserName=user, PolicyName="sim2real-inline"),
    )
    _assert_encoded_once("GetUserPolicy response", raw, PERMISSIONS_POLICY)

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    arn = iam.create_policy(
        PolicyName=policy_name, Path=path, PolicyDocument=PERMISSIONS_POLICY, Tags=_TAGS
    )["Policy"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_policy(PolicyArn=arn), "NoSuchEntity"))
    raw = _raw_elements(
        iam, "GetPolicyVersion", "Document",
        lambda: iam.get_policy_version(PolicyArn=arn, VersionId="v1"),
    )
    _assert_encoded_once("GetPolicyVersion response", raw, PERMISSIONS_POLICY)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
