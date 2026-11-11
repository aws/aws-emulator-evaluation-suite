"""iam-bound-deep-iam-3-managed-policy-version-over-6144-significant-chars-rejected."""
from __future__ import annotations

import json
import urllib.parse

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-managed-policy-version-over-6144-significant-chars-rejected"
GROUP = "policy-size-limits"
SERVICES = ["iam"]

# IAM quotas reference: "Managed policy size: 6,144 characters" -- NOT adjustable, so a fixed
# API constant rather than an account quota. IAM does not count whitespace toward it.
_MANAGED_POLICY_SIZE = 6144


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicyVersion's 6,144-char limit excludes whitespace: 6,140 and 6,144 significant chars
    plus ~4 KB whitespace are accepted intact; 6,145 gets LimitExceeded, adds no version, and its
    SetAsDefault=True leaves the default version unchanged."""
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-psv-")
    path = f"/{base}/"
    small = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": _PAD_ARN + "v1"}]}
    pol = iam.create_policy(PolicyName=base, Path=path, PolicyDocument=json.dumps(small))["Policy"]
    arn = pol["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, arn))

    # ---- positive controls: 6,140 and exactly 6,144 significant chars, both raw-oversize ----
    accepted: dict[str, dict] = {}
    for n, make_default in ((6140, True), (_MANAGED_POLICY_SIZE, False)):
        doc = _doc_of(n)
        text = _padded(doc)
        assert _significant(text) == n and len(text) > _MANAGED_POLICY_SIZE + 4000, (
            f"construction: {_significant(text)!r} significant / {len(text)!r} raw"
        )
        ver = iam.create_policy_version(PolicyArn=arn, PolicyDocument=text, SetAsDefault=make_default)["PolicyVersion"]
        accepted[ver["VersionId"]] = doc
        got = _as_doc(iam.get_policy_version(PolicyArn=arn, VersionId=ver["VersionId"])["PolicyVersion"]["Document"])
        assert got == doc, f"version {ver['VersionId']!r} ({n} significant chars) did not read back intact"
    assert sorted(accepted) == ["v2", "v3"], f"accepted versions were {sorted(accepted)!r}, expected v2 and v3"

    # ---- negative: 6,145 significant chars is REJECTED with LimitExceeded ----
    over_text = _padded(_doc_of(_MANAGED_POLICY_SIZE + 1))
    assert _significant(over_text) == _MANAGED_POLICY_SIZE + 1, "construction: over document size"
    code, message = _rejection(
        lambda: iam.create_policy_version(PolicyArn=arn, PolicyDocument=over_text, SetAsDefault=True),
        "CreatePolicyVersion(6145 significant chars)",
    )
    assert code == "LimitExceeded", (
        f"CreatePolicyVersion over the managed size limit returned {code!r}, expected 'LimitExceeded'"
    )
    expected = "Cannot exceed quota for PolicySize: 6144"
    assert message == expected, f"message: expected {expected!r}, got {message!r}"

    # ---- effect absent: no version added, default pointer not moved by the rejected call ----
    versions = [v for page in iam.get_paginator("list_policy_versions").paginate(PolicyArn=arn)
                for v in page["Versions"]]
    ids = sorted(v["VersionId"] for v in versions)
    assert ids == ["v1", "v2", "v3"], f"versions after the rejected call: {ids!r}"
    defaults = [v["VersionId"] for v in versions if v["IsDefaultVersion"]]
    assert defaults == ["v2"], f"default version after the rejected SetAsDefault call: {defaults!r}"
    meta = iam.get_policy(PolicyArn=arn)["Policy"]
    assert meta["DefaultVersionId"] == "v2", f"GetPolicy DefaultVersionId={meta['DefaultVersionId']!r}"
    default_doc = _as_doc(iam.get_policy_version(PolicyArn=arn, VersionId="v2")["PolicyVersion"]["Document"])
    assert default_doc == accepted["v2"], "default version content changed after the rejected call"


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
