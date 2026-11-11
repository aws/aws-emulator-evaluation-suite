"""assume-role-source-identity-echoed."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-source-identity-echoed"
GROUP = 'credential-issuance'
SERVICES = ['sts']

# A management event can take over two minutes to become findable via LookupEvents; the budget
# leaves margin for that while staying inside the check's time limit.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SourceIdentity given to AssumeRole is echoed in the response and also recorded against the
    session: CloudTrail's record of a later GetCallerIdentity made with the session carries it.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    ct = ctx.client("cloudtrail")

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _drop_role(role_name):
        try:
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _client_from_creds(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )

    def _lookup_all(**kw):
        out = []
        pages = 0
        # LookupEvents is rate-limited per account; a throttled page is retried to a deadline.
        throttle_deadline = time.monotonic() + 30
        while pages < _PAGE_CEILING:
            try:
                resp = ct.lookup_events(**kw)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= throttle_deadline:
                    raise
                time.sleep(2)
                continue
            pages += 1
            out.extend(resp["Events"])
            nxt = resp.get("NextToken")
            if not nxt:
                return out
            kw["NextToken"] = nxt
        return out

    account_id = _account_id()
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))

    session_name = ctx.unique_name("sim2real-behav-sess-")
    source_identity = ctx.unique_name("sim2real-behav-srcid-")

    def _try_assume():
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, SourceIdentity=source_identity,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return None
            raise

    assume_resp = _poll_until(
        _try_assume, lambda r: r is not None, timeout_s=120, interval_s=3.0,
        description=f"role {role_arn} became assumable",
    )
    assert assume_resp.get("SourceIdentity") == source_identity, (
        "setup sanity check: AssumeRole's own response must echo the SourceIdentity it was given, "
        f"before the independent CloudTrail read below is even attempted; got "
        f"{assume_resp.get('SourceIdentity')!r}"
    )

    session_sts = _client_from_creds("sts", assume_resp["Credentials"])

    # The marker call: independent of the AssumeRole that minted the session, made WITH that
    # session, so its own CloudTrail record is the only place SourceIdentity could still be
    # observed if it is genuinely attached to the session rather than a one-shot echo.
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    marker_caller = session_sts.get_caller_identity()
    assert session_name in marker_caller["Arn"], (
        f"the marker call was not made with the SourceIdentity-carrying session: "
        f"{marker_caller['Arn']!r} does not contain {session_name!r}"
    )

    window_start = emitted_at - datetime.timedelta(minutes=2)
    record = None
    t0 = time.monotonic()
    left = ctx.time_left()
    budget_s = _INDEX_BUDGET_S if left is None else min(_INDEX_BUDGET_S, left)
    polls = 0
    while time.monotonic() - t0 < budget_s:
        polls += 1
        events = _lookup_all(
            StartTime=window_start,
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            MaxResults=50,
            # An assumed-role event's Username is the session name: one narrow page per poll.
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": session_name}],
        )
        for ev in events:
            body = ev.get("CloudTrailEvent", "")
            if ev.get("EventName") == "GetCallerIdentity" and session_name in body:
                record = json.loads(body)
                break
        if record is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert record is not None, (
        f"CloudTrail never produced an audit record for the GetCallerIdentity call made with the "
        f"SourceIdentity-carrying session {session_name!r}; {polls} polls over {waited:.0f}s found "
        f"none. A target that accepts SourceIdentity but does not record it against the session's "
        f"own subsequent activity fails here."
    )
    # sourceIdentity is nested under userIdentity.sessionContext, not directly on userIdentity.
    session_context = record["userIdentity"].get("sessionContext") or {}
    assert session_context.get("sourceIdentity") == source_identity, (
        f"CloudTrail's own record of a call made WITH this session reports "
        f"userIdentity.sessionContext.sourceIdentity={session_context.get('sourceIdentity')!r}, "
        f"expected {source_identity!r} -- the AssumeRole response echoed the value but the "
        f"session's recorded identity does not carry it through to independently-observed "
        f"activity."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
