"""iam-bound-deep-iam-3-role-inline-policy-over-10240-significant-chars-rejected."""
from __future__ import annotations

import json
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-role-inline-policy-over-10240-significant-chars-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "Role policy size: 10,240 characters" (aggregate of a role's inline
# policies) -- NOT adjustable, so a fixed API constant. IAM does not count whitespace toward it.
_ROLE_POLICY_SIZE = 10240
_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRolePolicy's 10,240-char limit excludes whitespace: 10,241 significant chars gets
    LimitExceeded and stores nothing, 10,240 plus ~4 KB whitespace is accepted and read back intact,
    and replacing it with 10,241 gets LimitExceeded leaving the stored policy unchanged."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-psr-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=_TRUST, Description="sim2real policy-size check")
    ctx.on_cleanup(lambda: _delete_role_fully(iam, role))

    over_text = _padded(_doc_of(_ROLE_POLICY_SIZE + 1))
    assert _significant(over_text) == _ROLE_POLICY_SIZE + 1, "construction: over document size"

    # ---- negative on an empty role: 10,241 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_role_policy(RoleName=role, PolicyName="over", PolicyDocument=over_text),
        "PutRolePolicy(10241 significant chars, empty role)",
    )
    assert code == "LimitExceeded", f"PutRolePolicy over the role limit returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 10240 bytes exceeded for role {role}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _role_policy_names(iam, role)
    assert names == [], f"rejected inline policy left state behind: ListRolePolicies={names!r}"

    # ---- positive control: exactly 10,240 significant chars + ~4 KB whitespace is ACCEPTED ----
    at_doc = _doc_of(_ROLE_POLICY_SIZE)
    at_text = _padded(at_doc)
    assert _significant(at_text) == _ROLE_POLICY_SIZE and len(at_text) > _ROLE_POLICY_SIZE + 4000, (
        f"construction: {_significant(at_text)!r} significant / {len(at_text)!r} raw"
    )
    iam.put_role_policy(RoleName=role, PolicyName="at-limit", PolicyDocument=at_text)
    got = _as_doc(iam.get_role_policy(RoleName=role, PolicyName="at-limit")["PolicyDocument"])
    assert got == at_doc, "GetRolePolicy did not read back the 10,240-character policy intact"

    # ---- negative on replace: the same name with 10,241 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_role_policy(RoleName=role, PolicyName="at-limit", PolicyDocument=over_text),
        "PutRolePolicy(replace with 10241 significant chars)",
    )
    assert code == "LimitExceeded", f"replacing with an oversize document returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 10240 bytes exceeded for role {role}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _role_policy_names(iam, role)
    assert names == ["at-limit"], f"ListRolePolicies after the rejected replace: {names!r}"
    still = _as_doc(iam.get_role_policy(RoleName=role, PolicyName="at-limit")["PolicyDocument"])
    assert still == at_doc, "the rejected replace modified the stored 10,240-character policy"


def _role_policy_names(iam, role: str) -> list[str]:
    return sorted(n for page in iam.get_paginator("list_role_policies").paginate(RoleName=role)
                  for n in page["PolicyNames"])


def _delete_role_fully(iam, role: str) -> None:
    from botocore.exceptions import ClientError
    try:
        names = _role_policy_names(iam, role)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for n in names:
        _quiet(lambda n=n: iam.delete_role_policy(RoleName=role, PolicyName=n))
    _quiet(lambda: iam.delete_role(RoleName=role))


_PAD_ARN = "arn:aws:s3:::sim2real-size-pad/"


def _compact_len(doc: dict) -> int:
    return len(json.dumps(doc, separators=(",", ":")))


def _significant(text: str) -> int:
    return sum(1 for ch in text if not ch.isspace())


def _doc_of(significant: int) -> dict:
    """A valid identity policy whose compact JSON is exactly `significant` characters, none of
    them whitespace, grown by appending S3 object ARNs."""
    doc = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": [_PAD_ARN + "k"]}]}
    res = doc["Statement"][0]["Resource"]
    while (gap := significant - _compact_len(doc)) > 0:
        room = 200 - (len(res[-1]) - len(_PAD_ARN))
        if room > 0:
            res[-1] += "k" * min(room, gap)
        elif gap >= 3 + len(_PAD_ARN) + 1:
            res.append(_PAD_ARN + "k")
        else:
            res[-1] += "k" * gap
    assert _compact_len(doc) == significant, f"construction: built {_compact_len(doc)!r}, wanted {significant!r}"
    return doc


def _padded(doc: dict, whitespace: int = 4096) -> str:
    """The document re-serialised with ~`whitespace` characters of insignificant whitespace."""
    text = json.dumps(doc, indent=1)
    have = len(text) - _significant(text)
    per = max(1, (whitespace - have) // text.count("\n") + 1)
    text = text.replace("\n", "\n" + " " * per)
    assert len(text) - _significant(text) >= whitespace, "construction: pad too small"
    assert json.loads(text) == doc, "construction: padding changed the document"
    return text


def _as_doc(value):
    if isinstance(value, dict):
        return value
    return json.loads(urllib.parse.unquote(value))


def _rejection(fn, what: str, on_accept=None) -> tuple[str, str]:
    """ClientError (code, message) of fn(); on success, hand the result to on_accept and raise."""
    from botocore.exceptions import ClientError
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    if on_accept is not None:
        on_accept(resp)
    raise AssertionError(f"{what} was expected to be rejected but SUCCEEDED")


def _list_local_policy_names(iam, path: str) -> list[str]:
    names: list[str] = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", PathPrefix=path):
        names.extend(p["PolicyName"] for p in page["Policies"])
    return sorted(names)


def _quiet(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_policy_fully(iam, arn: str) -> None:
    """Delete every non-default version, then the policy; indifferent to prior cleanup state."""
    from botocore.exceptions import ClientError
    try:
        versions = [v for page in iam.get_paginator("list_policy_versions").paginate(PolicyArn=arn)
                    for v in page["Versions"]]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for v in versions:
        if not v["IsDefaultVersion"]:
            _quiet(lambda vid=v["VersionId"]: iam.delete_policy_version(PolicyArn=arn, VersionId=vid))
    _quiet(lambda: iam.delete_policy(PolicyArn=arn))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
