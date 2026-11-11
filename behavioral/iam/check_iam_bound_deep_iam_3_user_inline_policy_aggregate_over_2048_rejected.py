"""iam-bound-deep-iam-3-user-inline-policy-aggregate-over-2048-rejected."""
from __future__ import annotations

import json
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-user-inline-policy-aggregate-over-2048-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "User policy size: 2,048 characters" -- the AGGREGATE of all of a user's
# inline policies, NOT adjustable, so a fixed API constant. Whitespace and policy names do not count.
_USER_POLICY_SIZE = 2048


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The 2,048-character user inline-policy limit is an aggregate: policies of 1,000 + 1,048 characters
    are accepted, a third one and growing the second to 1,049 fail with the exact LimitExceeded and change
    nothing, and shrinking the second to 848 makes room for the same third policy."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-psa-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_fully(iam, user))

    doc_a, doc_b, doc_c = _doc_of(1000), _doc_of(1048), _doc_of(200)
    assert 1000 + 1048 == _USER_POLICY_SIZE, "construction: a + b must fill the limit exactly"

    def put(name, doc):
        iam.put_user_policy(UserName=user, PolicyName=name, PolicyDocument=json.dumps(doc, separators=(",", ":")))

    def read(name):
        return _as_doc(iam.get_user_policy(UserName=user, PolicyName=name)["PolicyDocument"])

    # ---- positive: two policies summing to exactly the limit are both accepted ----
    put("a", doc_a)
    put("b", doc_b)
    assert _user_policy_names(iam, user) == ["a", "b"], f"after a+b: {_user_policy_names(iam, user)!r}"

    # ---- negative: a third, small policy pushes the aggregate over the limit ----
    code, message = _rejection(lambda: put("c", doc_c), "PutUserPolicy(c, aggregate 2248)")
    assert code == "LimitExceeded", f"third policy over the aggregate returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 2048 bytes exceeded for user {user}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _user_policy_names(iam, user)
    assert names == ["a", "b"], f"rejected policy 'c' left state behind: ListUserPolicies={names!r}"

    # ---- negative: growing b by one character is rejected and b is untouched ----
    code, message = _rejection(lambda: put("b", _doc_of(1049)), "PutUserPolicy(b -> 1049, aggregate 2049)")
    assert code == "LimitExceeded", f"growing b over the aggregate returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 2048 bytes exceeded for user {user}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    assert read("b") == doc_b, "the rejected grow modified stored policy 'b'"

    # ---- positive: shrinking b frees exactly the room the same third policy needs ----
    doc_b_small = _doc_of(848)
    assert 1000 + 848 + 200 == _USER_POLICY_SIZE, "construction: a + small b + c must fill the limit exactly"
    put("b", doc_b_small)
    put("c", doc_c)
    names = _user_policy_names(iam, user)
    assert names == ["a", "b", "c"], f"after shrink + c: {names!r}"
    assert read("a") == doc_a, "policy 'a' changed"
    assert read("b") == doc_b_small, "policy 'b' did not take the shrunk document"
    assert read("c") == doc_c, "policy 'c' did not read back intact"


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
