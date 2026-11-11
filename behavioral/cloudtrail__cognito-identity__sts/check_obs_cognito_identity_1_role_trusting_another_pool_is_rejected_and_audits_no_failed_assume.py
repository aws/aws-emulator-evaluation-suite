"""obs-cognito-identity-1-role-trusting-another-pool-is-rejected-and-audits-no-failed-assume."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-identity-1-role-trusting-another-pool-is-rejected-and-audits-no-failed-assume"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-identity", "sts"]

_MARKER_CEILING_S = 600.0
_DEADLINE_MULTIPLE = 4.0
_STS_FLOOR_S = 60.0
_STS_CEILING_S = 900.0
#: After the barrier record surfaces, hold for this multiple of the marker latency (bounded) and
#: scan again, so a refused attempt indexed slightly later than the barrier is still caught.
_HOLD_MULTIPLE = 1.0
_HOLD_CEILING_S = 300.0
_PROPAGATION_BUDGET_S = 120.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_REFUSED_ATTEMPTS = 3

_REFUSAL = "InvalidIdentityPoolConfigurationException"
_REFUSAL_MESSAGE = (
    "Invalid identity pool configuration. Check assigned IAM roles for this pool."
)

def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Returns (events, pages)."""
    out = []
    nxt = None
    for page in range(1, _PAGE_CEILING + 1):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out, page
    raise AssertionError(
        f"LookupEvents paged past {_PAGE_CEILING} pages without exhausting; refusing to assert "
        "membership in a truncated result"
    )


def _records(ct, event_name, start, predicate):
    """All records for `event_name` satisfying `predicate`. Returns (records, pages, n_events)."""
    events, pages = _lookup_all(
        ct,
        StartTime=start,
        EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
    )
    hits = [r for r in (json.loads(ev["CloudTrailEvent"]) for ev in events) if predicate(r)]
    return hits, pages, len(events)


def _params(raw):
    return raw.get("requestParameters") or {}


def _error(fn):
    """Return (code, message) of the AWS error `fn` raised; raise if the call succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned keys {sorted(resp)!r}"
    )


def _trust(aud):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": aud},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _vend_with_retry(ci, identity_id, token, why):
    """GetCredentialsForIdentity, retrying only the trust-propagation refusal within a bound."""
    deadline = time.monotonic() + _PROPAGATION_BUDGET_S
    while True:
        try:
            return ci.get_credentials_for_identity(
                IdentityId=identity_id, Logins={"cognito-identity.amazonaws.com": token}
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if code != _REFUSAL or message != _REFUSAL_MESSAGE or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{why}: GetCredentialsForIdentity did not vend within "
                    f"{_PROPAGATION_BUDGET_S:.0f}s; last error {code!r} ({message!r})"
                ) from exc
            time.sleep(3.0)


def _pool(ctx, ci, label):
    name = ctx.unique_name(f"sim2real_xsvc_ctneg_{label}_").replace("-", "_")
    provider = f"sim2real.{label}.{name[-12:]}"
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=provider,
        IdentityPoolTags={"sim2real": CHECK[:64]},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return name, pool_id, provider


@tags(
    "axis:rejection",
    "dp:api",
    "plane:data",
    "concern:negative-classes",
    "concern:eventing",
    "concern:e2e",
    "cap:c2",
)
def run(ctx) -> None:
    """GetCredentialsForIdentity is refused when the pool's role trusts another pool's aud, and the
    refusal leaves no failed AssumeRoleWithWebIdentity in CloudTrail; fixing only the trust vends.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/role-trust-and-permissions.html
    """
    ct = ctx.client("cloudtrail")
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    t0 = time.monotonic()
    ctl_name, ctl_pool, ctl_provider = _pool(ctx, ci, "ctl")
    _, bad_pool, bad_provider = _pool(ctx, ci, "bad")

    # Control role trusts the control pool. The broken role ALSO trusts the control pool, but is
    # assigned to the OTHER pool: exactly one thing is wrong, the `aud` it names.
    ctl_role = ctx.unique_name("sim2real-xsvc-ctneg-ctl-")[:64]
    ctl_role_arn = iam.create_role(
        RoleName=ctl_role, AssumeRolePolicyDocument=_trust(ctl_pool),
        Tags=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, ctl_role))
    bad_role = ctx.unique_name("sim2real-xsvc-ctneg-bad-")[:64]
    bad_role_arn = iam.create_role(
        RoleName=bad_role, AssumeRolePolicyDocument=_trust(ctl_pool),
        Tags=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, bad_role))

    # SetIdentityPoolRoles is eventually consistent, so the broken pool is a separate pool whose
    # role is wrong from the start, and the repair edits the role's trust, not the assignment.
    ci.set_identity_pool_roles(IdentityPoolId=ctl_pool, Roles={"authenticated": ctl_role_arn})
    ci.set_identity_pool_roles(IdentityPoolId=bad_pool, Roles={"authenticated": bad_role_arn})
    assigned = ci.get_identity_pool_roles(IdentityPoolId=bad_pool).get("Roles", {})
    assert assigned.get("authenticated") == bad_role_arn, (
        f"the broken pool must report the role it was given: expected {bad_role_arn!r}, actual "
        f"{assigned!r}"
    )

    ctl_login = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=ctl_pool, Logins={ctl_provider: "user-ctl"}
    )
    bad_login = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=bad_pool, Logins={bad_provider: "user-bad"}
    )
    bad_identity = bad_login["IdentityId"]

    # Positive control first: the identically-shaped wiring vends, so trust propagation is done.
    ctl_vend = _vend_with_retry(ci, ctl_login["IdentityId"], ctl_login["Token"], "control pool")
    assert ctl_vend["Credentials"].get("AccessKeyId"), (
        f"the control pool vended no access key: {sorted(ctl_vend['Credentials'])!r}"
    )

    # The negative: every attempt on the broken pool is refused with the exact code and message.
    for attempt in range(1, _REFUSED_ATTEMPTS + 1):
        code, message = _error(lambda: ci.get_credentials_for_identity(
            IdentityId=bad_identity, Logins={"cognito-identity.amazonaws.com": bad_login["Token"]}
        ))
        assert code == _REFUSAL, (
            f"attempt {attempt}: a role trusting another pool's aud must be refused with "
            f"{_REFUSAL!r}, actual {code!r}"
        )
        assert message == _REFUSAL_MESSAGE, (
            f"attempt {attempt}: expected refusal message {_REFUSAL_MESSAGE!r}, actual {message!r}"
        )

    # Repair exactly the one broken thing — the role's trust — and the same identity now vends.
    iam.update_assume_role_policy(RoleName=bad_role, PolicyDocument=_trust(bad_pool))
    repaired = _vend_with_retry(ci, bad_identity, bad_login["Token"], "repaired pool")
    assert repaired["IdentityId"] == bad_identity, (
        f"the repaired vend answered for {repaired.get('IdentityId')!r}, not {bad_identity!r}"
    )
    repaired_key = repaired["Credentials"]["AccessKeyId"]
    t_repair = time.monotonic()

    # Calibrate CloudTrail index latency on this run's own CreateIdentityPool record.
    while True:
        hits, pages, n_events = _records(
            ct, "CreateIdentityPool", window_start,
            lambda r: _params(r).get("identityPoolName") == ctl_name,
        )
        if hits:
            break
        assert time.monotonic() - t0 < _MARKER_CEILING_S, (
            f"CloudTrail event history never surfaced this run's own CreateIdentityPool for "
            f"{ctl_name!r} within {_MARKER_CEILING_S:.0f}s (last scan: {pages} page(s), "
            f"{n_events} events); the absence below cannot be judged against a dead index"
        )
        time.sleep(_POLL_INTERVAL_S)
    marker_latency_s = time.monotonic() - t0
    deadline_s = min(max(_DEADLINE_MULTIPLE * marker_latency_s, _STS_FLOOR_S), _STS_CEILING_S)

    def _about_bad_role(r):
        return _params(r).get("roleArn") == bad_role_arn

    # Barrier: the repaired vend follows every refused attempt, so once its record surfaces an
    # audited refusal would have surfaced too; a further calibrated hold then rescans.
    polls = 0
    while True:
        polls += 1
        recs, pages, n_events = _records(
            ct, "AssumeRoleWithWebIdentity", window_start, _about_bad_role
        )
        if any(((r.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId")
               == repaired_key for r in recs):
            break
        assert time.monotonic() - t_repair < deadline_s, (
            f"barrier never arrived: no AssumeRoleWithWebIdentity record for the repaired vend "
            f"(roleArn {bad_role_arn!r}, accessKeyId {repaired_key!r}) within {deadline_s:.0f}s "
            f"({_DEADLINE_MULTIPLE}x the {marker_latency_s:.0f}s marker latency) after {polls} "
            f"polls; last scan returned {pages} page(s), {n_events} events, {len(recs)} naming "
            f"the role"
        )
        time.sleep(_POLL_INTERVAL_S)

    def _assert_no_failed_assume(when):
        recs, _, _ = _records(ct, "AssumeRoleWithWebIdentity", window_start, _about_bad_role)
        errored = [r.get("errorCode") for r in recs if r.get("errorCode")]
        assert not errored, (
            f"{when}: the {_REFUSED_ATTEMPTS} refused attempts must leave no failed "
            f"AssumeRoleWithWebIdentity in the role owner's event history, yet "
            f"{len(errored)} record(s) naming {bad_role_arn!r} carry errorCode(s) {errored!r}"
        )
        keys = sorted({
            ((r.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId") or "<none>"
            for r in recs
        })
        assert keys == [repaired_key], (
            f"{when}: every record naming the broken role must be the repaired vend's own; expected "
            f"access keys [{repaired_key!r}], actual {keys!r}"
        )
        users = sorted({(r.get("userIdentity") or {}).get("userName") or "<none>" for r in recs})
        assert users == [bad_identity], (
            f"{when}: the broken role's records must all be for identity {bad_identity!r}, actual "
            f"{users!r}"
        )

    _assert_no_failed_assume("at the barrier")
    hold_s = min(_HOLD_MULTIPLE * marker_latency_s, _HOLD_CEILING_S)
    hold_until = time.monotonic() + hold_s
    scans = 0
    while time.monotonic() < hold_until:
        time.sleep(_POLL_INTERVAL_S)
        scans += 1
        _assert_no_failed_assume(f"hold scan {scans} of a {hold_s:.0f}s calibrated hold")
    _assert_no_failed_assume(f"after holding a further {hold_s:.0f}s ({scans} scans)")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
