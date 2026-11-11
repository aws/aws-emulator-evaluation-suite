"""source-identity-propagates-from-assume-role-into-the-sessions-own-audit-records."""

# A SourceIdentity passed to AssumeRole is recorded in that event's requestParameters and in
# userIdentity.sessionContext of every call the session makes, persists across a chained session
# that supplies none, and is absent from a session assumed without one (the twin control).
# A regional STS endpoint is used, so the records land in ctx.region's event history.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "source-identity-propagates-from-assume-role-into-the-sessions-own-audit-records"
GROUP = "eventing"
SERVICES = ["cloudtrail", "sts"]

# Marks a failure as missing audit behavior rather than a connection or not-implemented error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0
_PROPAGATION_BUDGET_S = 90.0  # a new trust policy becoming usable by AssumeRole
_ROLE_PRINCIPAL_BUDGET_S = 95.0  # a new role becoming a valid trust-policy principal
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# The source identity value. The sts model constrains it to alphanumerics plus +=,.@- with no
# spaces and no "aws:" prefix, so a uuid hex fragment is inside the grammar.
_SOURCE_IDENTITY_PREFIX = "simparity"

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Never assert membership in one page."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    raise AssertionError(
        f"{DATAPLANE_MARKER}: LookupEvents paged past {_PAGE_CEILING} pages without exhausting; "
        "refusing to assert membership in a truncated result"
    )


def _raw(event):
    """The full CloudTrail record. `CloudTrailEvent` is a JSON STRING, not a nested object."""
    return json.loads(event["CloudTrailEvent"])


def _await_record(ct, event_name, start, predicate, why, budget_s=_INDEX_BUDGET_S):
    """Poll event history from `start` until one record for `event_name` satisfies `predicate`.
    Raises."""
    deadline = time.monotonic() + budget_s
    seen = 0
    while True:
        events = _lookup_all(
            ct,
            StartTime=start,
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
        )
        seen = len(events)
        for ev in events:
            raw = _raw(ev)
            if predicate(raw):
                return raw
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no {event_name} record satisfying {why} within "
                f"{budget_s:.0f}s; expected 1, actual 0 of {seen} {event_name} records examined"
            )
        time.sleep(_POLL_INTERVAL_S)


def _assume_with_retry(sts, role_arn, session_name, source_identity=None):
    """AssumeRole, retrying only the trust-propagation error class, bounded, then raising."""
    kw = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": 3600}
    if source_identity is not None:
        kw["SourceIdentity"] = source_identity
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    caller_arn = sts.get_caller_identity()["Arn"]
    not_yet = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}"
    last = None
    while True:
        try:
            return sts.assume_role(**kw)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            last = code
            # AccessDenied here is the newly-written trust policy not yet in effect. It is retried
            # ONLY until the deadline and then raises -- it is never swallowed.
            if code != "AccessDenied" or message != not_yet or time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssumeRole on {role_arn} did not become usable within "
                    f"{_PROPAGATION_BUDGET_S:.0f}s; expected success, actual error code {last!r} ({message!r})"
                ) from exc
            time.sleep(5.0)


def _creds(assume_response):
    c = assume_response["Credentials"]
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _delete_role_completely(iam, role_name):
    """Idempotent teardown for exactly the role this check created -- never a prefix sweep."""
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


def _create_role_with_retry(iam, name, trust, budget_s=_ROLE_PRINCIPAL_BUDGET_S):
    """CreateRole, retrying only the trust-principal-propagation error class, bounded, then raising.

    A trust policy naming a just-created role ARN as Principal is transiently rejected with
    MalformedPolicyDocument ("Invalid principal in policy") until the new role is visible IAM-wide.
    """
    deadline = time.monotonic() + budget_s
    principal = trust["Statement"][0]["Principal"]["AWS"]
    not_yet = f'Invalid principal in policy: "AWS":"{principal}"'
    last = None
    while True:
        try:
            return iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            last = code
            if (
                code != "MalformedPolicyDocument"
                or msg != not_yet
                or time.monotonic() >= deadline
            ):
                raise AssertionError(
                    f"CreateRole for {name} did not become possible within {budget_s:.0f}s; "
                    f"expected success, actual error code {last!r} ({msg!r})"
                ) from exc
            time.sleep(5.0)


def _create_role(ctx, iam, name, trust, inline):
    _create_role_with_retry(iam, name, trust)
    ctx.on_cleanup(lambda: _delete_role_completely(iam, name))
    iam.put_role_policy(
        RoleName=name, PolicyName="simparity-inline", PolicyDocument=json.dumps(inline)
    )
    return iam.get_role(RoleName=name)["Role"]["Arn"]


def _session_context(raw):
    return (raw.get("userIdentity") or {}).get("sessionContext") or {}


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c7",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A session's source identity is recorded at AssumeRole AND on every call the session makes,
    survives a role chain, and is absent from a session that never set one.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    iam = ctx.client("iam")
    # A REGIONAL STS client, so the records land in ctx.region's event history.
    sts = ctx.client("sts", region=ctx.region)
    ct = ctx.client("cloudtrail", region=ctx.region)

    nonce = ctx.unique_name("").replace("-", "")[:12]
    # Event history is read only from just before this run, never over the account's 90 days.
    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    source_identity = f"{_SOURCE_IDENTITY_PREFIX}{nonce}"

    root = f"arn:aws:iam::{account_id}:root"

    # The launcher: a role this check creates, whose session makes every AssumeRole graded below,
    # so the caller the AssumeRole record must name is a principal the check itself minted.
    launch_name = ctx.unique_name("simparity-ct-sts-launch-")
    launch_arn = _create_role(
        ctx,
        iam,
        launch_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": root}, "Action": ["sts:AssumeRole"]}
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                    "Resource": "*",
                }
            ],
        },
    )
    launch = _assume_with_retry(sts, launch_arn, f"launch{nonce}")
    caller_arn = launch["AssumedRoleUser"]["Arn"]
    launch_sts = ctx.client("sts", region=ctx.region, creds=_creds(launch))

    # Role A: assumable by this account, and permitted to SET a source identity. Without
    # sts:SetSourceIdentity in the trust policy the AssumeRole call is refused outright.
    first_name = ctx.unique_name("simparity-ct-sts-first-")
    first_arn = _create_role(
        ctx,
        iam,
        first_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": root},
                    "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                }
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": "*"}],
        },
    )

    # Role B: assumable only by role A, so reaching it proves the chain really happened.
    chain_name = ctx.unique_name("simparity-ct-sts-chain-")
    chain_arn = _create_role(
        ctx,
        iam,
        chain_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": first_arn},
                    "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                }
            ],
        },
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
    )

    # Role C: the twin control. Identical shape, assumed WITHOUT a SourceIdentity.
    bare_name = ctx.unique_name("simparity-ct-sts-bare-")
    bare_arn = _create_role(
        ctx,
        iam,
        bare_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": root}, "Action": ["sts:AssumeRole"]}
            ],
        },
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
    )

    # ---- the three sessions, and one marker call each ------------------------------------------
    first_session = f"first{nonce}"
    chain_session = f"chain{nonce}"
    bare_session = f"bare{nonce}"

    first = _assume_with_retry(launch_sts, first_arn, first_session, source_identity)
    first_assumed_arn = first["AssumedRoleUser"]["Arn"]
    assert first.get("SourceIdentity") == source_identity, (
        "AssumeRole did not echo the SourceIdentity it was given: expected "
        f"{source_identity!r}, actual {first.get('SourceIdentity')!r}"
    )

    first_sts = ctx.client("sts", region=ctx.region, creds=_creds(first))
    # GetCallerIdentity requires no permission at all, so this marker cannot fail for authorisation
    # reasons and is therefore a clean probe of what the audit record says about the SESSION.
    first_sts.get_caller_identity()

    chain = _assume_with_retry(first_sts, chain_arn, chain_session)
    chain_sts = ctx.client("sts", region=ctx.region, creds=_creds(chain))
    chain_sts.get_caller_identity()

    bare = _assume_with_retry(launch_sts, bare_arn, bare_session)
    bare_sts = ctx.client("sts", region=ctx.region, creds=_creds(bare))
    bare_sts.get_caller_identity()

    # ---- terminal reads, all at CloudTrail, via an operation none of the above used -------------
    # Row 1: the AssumeRole record for the session that SET a source identity.
    assume_record = _await_record(
        ct,
        "AssumeRole",
        window_start,
        lambda r: (r.get("requestParameters") or {}).get("roleSessionName") == first_session,
        f"requestParameters.roleSessionName == {first_session!r}",
    )
    req = assume_record.get("requestParameters") or {}
    assert req.get("sourceIdentity") == source_identity, (
        "the AssumeRole record did not carry the source identity in requestParameters: expected "
        f"{source_identity!r}, actual {req.get('sourceIdentity')!r}"
    )
    assert req.get("roleArn") == first_arn, (
        f"AssumeRole requestParameters.roleArn: expected {first_arn!r}, actual {req.get('roleArn')!r}"
    )
    resp_elems = assume_record.get("responseElements") or {}
    assumed = (resp_elems.get("assumedRoleUser") or {}).get("arn")
    assert assumed == first_assumed_arn, (
        "the AssumeRole record's responseElements.assumedRoleUser.arn must equal the ARN STS "
        f"returned to the caller: expected {first_assumed_arn!r}, actual {assumed!r}"
    )
    assert assume_record.get("eventSource") == "sts.amazonaws.com", (
        "AssumeRole eventSource: expected 'sts.amazonaws.com', actual "
        f"{assume_record.get('eventSource')!r}"
    )
    assert assume_record.get("errorCode") is None, (
        "a SUCCESSFUL AssumeRole must record no errorCode: expected None, actual "
        f"{assume_record.get('errorCode')!r}"
    )
    # The AssumeRole call itself was made by the launcher session, so the record must attribute
    # it to that CALLER and not to the role being assumed.
    assume_caller = (assume_record.get("userIdentity") or {}).get("arn")
    assert assume_caller == caller_arn, (
        "the AssumeRole record must attribute the call to the principal that made it, not to the "
        f"role it minted: expected {caller_arn!r}, actual {assume_caller!r}"
    )

    # Row 1b: the session's OWN call carries the source identity in sessionContext.
    first_call = _await_record(
        ct,
        "GetCallerIdentity",
        window_start,
        lambda r: first_session in ((r.get("userIdentity") or {}).get("arn") or ""),
        f"userIdentity.arn naming session {first_session!r}",
    )
    fc_ident = first_call.get("userIdentity") or {}
    assert fc_ident.get("type") == "AssumedRole", (
        f"userIdentity.type for a role session: expected 'AssumedRole', actual "
        f"{fc_ident.get('type')!r}"
    )
    fc_ctx = _session_context(first_call)
    issuer_arn = (fc_ctx.get("sessionIssuer") or {}).get("arn")
    assert issuer_arn == first_arn, (
        "sessionContext.sessionIssuer.arn must be the ROLE arn, not the session arn: expected "
        f"{first_arn!r}, actual {issuer_arn!r}"
    )
    # Asserted BOTH ways on purpose: the doc names the sessionContext block but not the key path.
    in_block = source_identity in json.dumps(fc_ctx)
    at_key = fc_ctx.get("sourceIdentity") == source_identity
    assert in_block, (
        "the session's own call must record the source identity somewhere in sessionContext: "
        f"expected {source_identity!r} inside {json.dumps(fc_ctx)[:200]!r}, actual absent"
    )
    assert at_key, (
        "the source identity is inside sessionContext but NOT at sessionContext['sourceIdentity'] "
        f"-- correct the key, do not relax the assertion. expected {source_identity!r} at that key, "
        f"actual {fc_ctx.get('sourceIdentity')!r}; full block {json.dumps(fc_ctx)[:200]!r}"
    )

    # Row 2: the CHAINED session, which supplied no source identity of its own.
    chain_call = _await_record(
        ct,
        "GetCallerIdentity",
        window_start,
        lambda r: chain_session in ((r.get("userIdentity") or {}).get("arn") or ""),
        f"userIdentity.arn naming chained session {chain_session!r}",
    )
    chain_ctx = _session_context(chain_call)
    assert chain_ctx.get("sourceIdentity") == source_identity, (
        "a chained session must inherit the source identity of the session that assumed it: "
        f"expected {source_identity!r}, actual {chain_ctx.get('sourceIdentity')!r}; full block "
        f"{json.dumps(chain_ctx)[:200]!r}"
    )

    # Row 3: the twin control. Absence here is what makes rows 1-2 mean anything.
    bare_call = _await_record(
        ct,
        "GetCallerIdentity",
        window_start,
        lambda r: bare_session in ((r.get("userIdentity") or {}).get("arn") or ""),
        f"userIdentity.arn naming control session {bare_session!r}",
    )
    bare_ctx = _session_context(bare_call)
    assert "sourceIdentity" not in bare_ctx, (
        "a session assumed WITHOUT SourceIdentity must record none: expected the key to be absent "
        f"from sessionContext, actual {bare_ctx.get('sourceIdentity')!r}; stamping a constant "
        "source identity on every session fails exactly here"
    )
    assert source_identity not in json.dumps(bare_ctx), (
        "the control session's sessionContext must not contain the OTHER session's source identity "
        f"anywhere: expected {source_identity!r} absent, actual present in "
        f"{json.dumps(bare_ctx)[:200]!r}"
    )
    # And the control session IS audited -- so row 3's absence is a real absence and not a target
    # that failed to record the control at all.
    assert (bare_ctx.get("sessionIssuer") or {}).get("arn") == bare_arn, (
        "the control session must itself be audited with its own issuer: expected "
        f"{bare_arn!r}, actual {(bare_ctx.get('sessionIssuer') or {}).get('arn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
