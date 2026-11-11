"""iam-bound-deep-iam-3-user-inline-policy-over-2048-significant-chars-rejected."""
from __future__ import annotations

import json
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-user-inline-policy-over-2048-significant-chars-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "User policy size: 2,048 characters" (aggregate of a user's inline
# policies) -- NOT adjustable, so a fixed API constant. IAM does not count whitespace toward it.
_USER_POLICY_SIZE = 2048


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutUserPolicy counts the 2,048-character user limit without whitespace: 2,049 characters fail with
    the exact LimitExceeded and store nothing, 2,048 padded to over 6 KB are accepted and read back
    intact, and replacing that policy with the 2,049-character one fails the same way and keeps it."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-psu-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_fully(iam, user))

    over_text = _padded(_doc_of(_USER_POLICY_SIZE + 1))
    assert _significant(over_text) == _USER_POLICY_SIZE + 1, "construction: over document size"

    # ---- negative on an empty user: 2,049 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_user_policy(UserName=user, PolicyName="over", PolicyDocument=over_text),
        "PutUserPolicy(2049 significant chars, empty user)",
    )
    assert code == "LimitExceeded", f"PutUserPolicy over the user limit returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 2048 bytes exceeded for user {user}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _user_policy_names(iam, user)
    assert names == [], f"rejected inline policy left state behind: ListUserPolicies={names!r}"

    # ---- positive control: exactly 2,048 significant chars + ~4 KB whitespace is ACCEPTED ----
    at_doc = _doc_of(_USER_POLICY_SIZE)
    at_text = _padded(at_doc)
    assert _significant(at_text) == _USER_POLICY_SIZE and len(at_text) > _USER_POLICY_SIZE + 4000, (
        f"construction: {_significant(at_text)!r} significant / {len(at_text)!r} raw"
    )
    iam.put_user_policy(UserName=user, PolicyName="at-limit", PolicyDocument=at_text)
    got = _as_doc(iam.get_user_policy(UserName=user, PolicyName="at-limit")["PolicyDocument"])
    assert got == at_doc, "GetUserPolicy did not read back the 2,048-character policy intact"

    # ---- negative on replace: the same name with 2,049 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_user_policy(UserName=user, PolicyName="at-limit", PolicyDocument=over_text),
        "PutUserPolicy(replace with 2049 significant chars)",
    )
    assert code == "LimitExceeded", f"replacing with an oversize document returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 2048 bytes exceeded for user {user}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _user_policy_names(iam, user)
    assert names == ["at-limit"], f"ListUserPolicies after the rejected replace: {names!r}"
    still = _as_doc(iam.get_user_policy(UserName=user, PolicyName="at-limit")["PolicyDocument"])
    assert still == at_doc, "the rejected replace modified the stored 2,048-character policy"


def _user_policy_names(iam, user: str) -> list[str]:
    return sorted(n for page in iam.get_paginator("list_user_policies").paginate(UserName=user)
                  for n in page["PolicyNames"])


def _delete_user_fully(iam, user: str) -> None:
    from botocore.exceptions import ClientError
    try:
        names = _user_policy_names(iam, user)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for n in names:
        _quiet(lambda n=n: iam.delete_user_policy(UserName=user, PolicyName=n))
    _quiet(lambda: iam.delete_user(UserName=user))


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
    """Return the ClientError (code, message) of fn()."""
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
