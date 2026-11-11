"""iam-bound-deep-iam-3-managed-policy-create-over-6144-significant-chars-rejected."""
from __future__ import annotations

import json
import time
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-managed-policy-create-over-6144-significant-chars-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "Managed policy size: 6,144 characters" -- NOT adjustable, so a fixed
# API constant rather than an account quota. IAM does not count whitespace toward it.
_MANAGED_POLICY_SIZE = 6144


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicy's 6,144-char limit excludes whitespace: 6,140 significant chars plus ~4 KB
    whitespace is accepted and reads back intact, while 6,145 with the same padding gets
    LimitExceeded and leaves no policy in ListPolicies."""
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-psz-")
    path = f"/{base}/"
    under_name = f"{base}-under"
    over_name = f"{base}-over"

    # ---- positive control: 6,140 significant chars + ~4 KB whitespace is ACCEPTED ----
    under_doc = _doc_of(6140)
    under_text = _padded(under_doc)
    assert _significant(under_text) == 6140, f"construction: {_significant(under_text)!r} significant chars"
    assert len(under_text) > _MANAGED_POLICY_SIZE + 4000, (
        f"construction: raw length {len(under_text)!r} must exceed the limit by the whitespace pad"
    )
    created = iam.create_policy(PolicyName=under_name, Path=path, PolicyDocument=under_text)["Policy"]
    under_arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, under_arn))
    assert created["DefaultVersionId"] == "v1", f"new policy default version {created['DefaultVersionId']!r}"

    back = iam.get_policy_version(PolicyArn=under_arn, VersionId="v1")["PolicyVersion"]
    assert back["IsDefaultVersion"] is True, f"v1 IsDefaultVersion={back['IsDefaultVersion']!r}"
    got = _as_doc(back["Document"])
    assert got == under_doc, (
        f"GetPolicyVersion did not read back the accepted document intact: "
        f"{_significant(json.dumps(got, separators=(',', ':')))!r} significant chars vs 6140"
    )

    # ---- negative: 6,145 significant chars, same padding, is REJECTED with LimitExceeded ----
    over_doc = _doc_of(6145)
    over_text = _padded(over_doc)
    assert _significant(over_text) == 6145, f"construction: {_significant(over_text)!r} significant chars"

    def _leaked(resp):
        leaked_arn = resp["Policy"]["Arn"]
        ctx.on_cleanup(lambda: _delete_policy_fully(iam, leaked_arn))

    code, message = _rejection(
        lambda: iam.create_policy(PolicyName=over_name, Path=path, PolicyDocument=over_text),
        "CreatePolicy(6145 significant chars)",
        on_accept=_leaked,
    )
    assert code == "LimitExceeded", f"CreatePolicy over the managed size limit returned {code!r}, expected 'LimitExceeded'"
    expected = "Cannot exceed quota for PolicySize: 6144"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"

    # ---- effect absent: the path-scoped listing shows the control and NOT the rejected name ----
    names: list[str] = []
    for _ in range(30):
        names = _list_local_policy_names(iam, path)
        if under_name in names:
            break
        time.sleep(1)
    assert under_name in names, f"accepted policy {under_name!r} never appeared under {path!r}: {names!r}"
    assert over_name not in names, f"rejected policy {over_name!r} is present in ListPolicies: {names!r}"
    assert names == [under_name], f"ListPolicies under the run-unique path returned {names!r}"

    over_arn = under_arn[: -len(under_name)] + over_name
    code, message = _rejection(lambda: iam.get_policy(PolicyArn=over_arn), "GetPolicy(rejected name)")
    assert code == "NoSuchEntity", f"GetPolicy on the rejected policy returned {code!r}, expected 'NoSuchEntity'"
    expected = f"Policy {over_arn} was not found."
    assert message == expected, f"message: expected {expected!r}, got {message!r}"


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
