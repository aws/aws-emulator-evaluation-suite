"""iam-bound-deep-iam-3-policy-size-whitespace-inside-strings-excluded-filled-rejected."""
from __future__ import annotations

import json
import time
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-policy-size-whitespace-inside-strings-excluded-filled-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference -- both NOT adjustable, so fixed API constants.
_MANAGED_POLICY_SIZE = 6144
_USER_POLICY_SIZE = 2048


def _with_inner_spaces(doc: dict, spaces: int, fill: str) -> dict:
    """Insert `spaces` characters of `fill` inside the LAST resource string, before its final
    character (inside the S3 object key, so the ARN stays well-formed)."""
    out = json.loads(json.dumps(doc))
    res = out["Statement"][0]["Resource"]
    res[-1] = res[-1][:-1] + fill * spaces + res[-1][-1:]
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IAM's size count excludes whitespace inside JSON strings: a 6,144-char managed policy with 40
    in-string spaces and a 2,048-char user inline policy with 20 are accepted with spaces preserved;
    filling those spaces with non-whitespace gets LimitExceeded."""
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-psw-")
    path = f"/{base}/"

    # ---- managed: 6,144 significant + 40 in-string spaces is ACCEPTED, read back intact ----
    m_ok = _with_inner_spaces(_doc_of(_MANAGED_POLICY_SIZE), 40, " ")
    m_ok_text = json.dumps(m_ok, separators=(",", ":"))
    assert _significant(m_ok_text) == _MANAGED_POLICY_SIZE and len(m_ok_text) == _MANAGED_POLICY_SIZE + 40, (
        f"construction: {_significant(m_ok_text)!r} significant / {len(m_ok_text)!r} raw"
    )
    pol = iam.create_policy(PolicyName=f"{base}-ok", Path=path, PolicyDocument=m_ok_text)["Policy"]
    ok_arn = pol["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, ok_arn))
    got = _as_doc(iam.get_policy_version(PolicyArn=ok_arn, VersionId="v1")["PolicyVersion"]["Document"])
    assert got == m_ok, "managed policy with in-string spaces did not read back intact (spaces lost or altered)"

    # ---- managed: the same 40 positions filled with 'k' (6,184 significant) is REJECTED ----
    m_bad_text = json.dumps(_with_inner_spaces(_doc_of(_MANAGED_POLICY_SIZE), 40, "k"), separators=(",", ":"))
    assert len(m_bad_text) == len(m_ok_text), "construction: filled document must have the same raw length"

    def _leaked(resp):
        leaked_arn = resp["Policy"]["Arn"]
        ctx.on_cleanup(lambda: _delete_policy_fully(iam, leaked_arn))

    code, message = _rejection(
        lambda: iam.create_policy(PolicyName=f"{base}-filled", Path=path, PolicyDocument=m_bad_text),
        "CreatePolicy(in-string spaces filled, 6184 significant)", on_accept=_leaked,
    )
    assert code == "LimitExceeded", f"filled managed document returned {code!r}, expected 'LimitExceeded'"
    expected = "Cannot exceed quota for PolicySize: 6144"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    names: list[str] = []
    for _ in range(30):
        names = _list_local_policy_names(iam, path)
        if f"{base}-ok" in names:
            break
        time.sleep(1)
    assert names == [f"{base}-ok"], f"ListPolicies under the run-unique path: {names!r}"

    # ---- user inline: 2,048 significant + 20 in-string spaces is ACCEPTED, read back intact ----
    user = f"{base}-u"
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_fully(iam, user))
    u_ok = _with_inner_spaces(_doc_of(_USER_POLICY_SIZE), 20, " ")
    u_ok_text = json.dumps(u_ok, separators=(",", ":"))
    assert _significant(u_ok_text) == _USER_POLICY_SIZE, "construction: user control size"
    iam.put_user_policy(UserName=user, PolicyName="p", PolicyDocument=u_ok_text)
    got = _as_doc(iam.get_user_policy(UserName=user, PolicyName="p")["PolicyDocument"])
    assert got == u_ok, "user inline policy with in-string spaces did not read back intact"

    # ---- user inline: replacing it with the filled (2,068 significant) document is REJECTED ----
    u_bad_text = json.dumps(_with_inner_spaces(_doc_of(_USER_POLICY_SIZE), 20, "k"), separators=(",", ":"))
    code, message = _rejection(
        lambda: iam.put_user_policy(UserName=user, PolicyName="p", PolicyDocument=u_bad_text),
        "PutUserPolicy(in-string spaces filled, 2068 significant)",
    )
    assert code == "LimitExceeded", f"filled user inline document returned {code!r}, expected 'LimitExceeded'"
    expected = f"Maximum policy size of 2048 bytes exceeded for user {user}"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"
    still = _as_doc(iam.get_user_policy(UserName=user, PolicyName="p")["PolicyDocument"])
    assert still == u_ok, "the rejected replace modified the stored user inline policy"


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
