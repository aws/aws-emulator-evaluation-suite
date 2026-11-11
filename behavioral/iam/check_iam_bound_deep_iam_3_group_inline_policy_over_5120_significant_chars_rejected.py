"""iam-bound-deep-iam-3-group-inline-policy-over-5120-significant-chars-rejected."""
from __future__ import annotations

import json
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-group-inline-policy-over-5120-significant-chars-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "Group policy size: 5,120 characters" (aggregate of a group's inline
# policies) -- NOT adjustable, so a fixed API constant. IAM does not count whitespace toward it.
_GROUP_POLICY_SIZE = 5120


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGroupPolicy's 5,120-char limit excludes whitespace: 5,121 significant chars gets
    LimitExceeded and stores nothing, 5,120 plus ~4 KB whitespace is accepted and reads back intact,
    and replacing it with 5,121 gets LimitExceeded leaving the stored policy unchanged."""
    iam = ctx.client("iam")
    group = ctx.unique_name("sim2real-psg-")
    iam.create_group(GroupName=group)
    ctx.on_cleanup(lambda: _delete_group_fully(iam, group))

    over_text = _padded(_doc_of(_GROUP_POLICY_SIZE + 1))
    assert _significant(over_text) == _GROUP_POLICY_SIZE + 1, "construction: over document size"

    # ---- negative on an empty group: 5,121 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_group_policy(GroupName=group, PolicyName="over", PolicyDocument=over_text),
        "PutGroupPolicy(5121 significant chars, empty group)",
    )
    assert code == "LimitExceeded", f"PutGroupPolicy over the group limit returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 5120 bytes exceeded for group {group}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _group_policy_names(iam, group)
    assert names == [], f"rejected inline policy left state behind: ListGroupPolicies={names!r}"

    # ---- positive control: exactly 5,120 significant chars + ~4 KB whitespace is ACCEPTED ----
    at_doc = _doc_of(_GROUP_POLICY_SIZE)
    at_text = _padded(at_doc)
    assert _significant(at_text) == _GROUP_POLICY_SIZE and len(at_text) > _GROUP_POLICY_SIZE + 4000, (
        f"construction: {_significant(at_text)!r} significant / {len(at_text)!r} raw"
    )
    iam.put_group_policy(GroupName=group, PolicyName="at-limit", PolicyDocument=at_text)
    got = _as_doc(iam.get_group_policy(GroupName=group, PolicyName="at-limit")["PolicyDocument"])
    assert got == at_doc, "GetGroupPolicy did not read back the 5,120-character policy intact"

    # ---- negative on replace: the same name with 5,121 significant chars is REJECTED ----
    code, message = _rejection(
        lambda: iam.put_group_policy(GroupName=group, PolicyName="at-limit", PolicyDocument=over_text),
        "PutGroupPolicy(replace with 5121 significant chars)",
    )
    assert code == "LimitExceeded", f"replacing with an oversize document returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 5120 bytes exceeded for group {group}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names = _group_policy_names(iam, group)
    assert names == ["at-limit"], f"ListGroupPolicies after the rejected replace: {names!r}"
    still = _as_doc(iam.get_group_policy(GroupName=group, PolicyName="at-limit")["PolicyDocument"])
    assert still == at_doc, "the rejected replace modified the stored 5,120-character policy"


def _group_policy_names(iam, group: str) -> list[str]:
    return sorted(n for page in iam.get_paginator("list_group_policies").paginate(GroupName=group)
                  for n in page["PolicyNames"])


def _delete_group_fully(iam, group: str) -> None:
    from botocore.exceptions import ClientError
    try:
        names = _group_policy_names(iam, group)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for n in names:
        _quiet(lambda n=n: iam.delete_group_policy(GroupName=group, PolicyName=n))
    _quiet(lambda: iam.delete_group(GroupName=group))


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
