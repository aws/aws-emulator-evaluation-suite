"""obs-cognito-idp-1-security-audit-telemetry."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-idp-1-security-audit-telemetry"
GROUP = "log-delivery"
SERVICES = ["cognito-idp", "logs"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

# userAuthEvents records take minutes (~2 min observed) to become readable via FilterLogEvents;
# this is a ceiling on a poll that raises.
_DELIVERY_BUDGET_S = 600
_POLL_S = 2


# timing:real-time — buffer: 120 s
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """Sign-ins on a Plus-tier pool with threat protection in AUDIT mode land in CloudWatch Logs as
    userAuthEvents SignIn records (Pass vs Fail, user, client and pool ids), and a sign-in made
    while delivery is cleared never arrives, bounded by a control pool and a restored-delivery one.
    """
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    group = f"/{ctx.unique_name('sim2real-xsvc-cip-sat-')}"
    logs.create_log_group(logGroupName=group, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    listed = [g for g in _all_groups(logs, group) if g["logGroupName"] == group]
    assert len(listed) == 1, f"log group {group!r} not listed exactly once after create: {listed!r}"
    group_arn = listed[0]["arn"][: -len(":*")] if listed[0]["arn"].endswith(":*") else listed[0]["arn"]

    pool, client = _audited_pool(ctx, idp, "sim2real-xsvc-cip-sat-pool-")
    ctrl_pool, ctrl_client = _audited_pool(ctx, idp, "sim2real-xsvc-cip-sat-ctrl-")
    for p in (pool, ctrl_pool):
        _set_delivery(idp, p, group_arn)

    marker = _user(ctx, idp, pool, "sim2real-mark-")
    quiet = _user(ctx, idp, pool, "sim2real-quiet-")
    repair = _user(ctx, idp, pool, "sim2real-repair-")
    ctrl = _user(ctx, idp, ctrl_pool, "sim2real-ctrl-")

    # Phase 1: one successful and one wrong-password USER_PASSWORD_AUTH, same marker user.
    ok = _sign_in(idp, client, marker)
    assert set(ok.get("AuthenticationResult", {})) >= {"AccessToken", "IdToken"}, (
        f"correct password did not yield tokens: {ok!r}")
    bad = _error(lambda: idp.initiate_auth(
        ClientId=client, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": marker[0], "PASSWORD": marker[1] + "x"}))
    assert bad == ("NotAuthorizedException", "Incorrect username or password."), (
        f"wrong password: expected NotAuthorizedException 'Incorrect username or password.', got {bad!r}")

    def phase1_done(recs):
        mine = [r for r in recs if r["message"].get("userName") == marker[0]]
        return ({r["message"].get("eventResponse") for r in mine} >= {"Pass", "Fail"}), mine

    mine = _await(logs, group, phase1_done, "the marker user's Pass and Fail sign-in records")
    for r in mine:
        m = r["message"]
        assert r.get("eventSource") == "USER_AUTH_EVENTS", f"eventSource {r.get('eventSource')!r} in {r!r}"
        assert m.get("eventType") == "SignIn", f"eventType {m.get('eventType')!r} in {r!r}"
        assert m.get("userPoolId") == pool, f"record names pool {m.get('userPoolId')!r}, expected {pool!r}"
        assert (r.get("logSourceId") or {}).get("userPoolId") == pool, f"logSourceId {r.get('logSourceId')!r}"
        assert m.get("clientId") == client, f"record names client {m.get('clientId')!r}, expected {client!r}"
    passes = {r["message"]["eventId"] for r in mine if r["message"].get("eventResponse") == "Pass"}
    fails = {r["message"]["eventId"] for r in mine if r["message"].get("eventResponse") == "Fail"}
    assert len(passes) == 1, f"expected ONE successful sign-in event, got eventIds {sorted(passes)!r}"
    assert len(fails) == 1, f"expected ONE failed sign-in event, got eventIds {sorted(fails)!r}"
    assert passes.isdisjoint(fails), f"one event labelled both Pass and Fail: {sorted(passes & fails)!r}"
    fail_challenges = [r["message"].get("challenges") for r in mine if r["message"]["eventId"] in fails]
    assert all("Password:Failure" in (c or []) for c in fail_challenges), (
        f"the failed attempt's records do not carry Password:Failure: {fail_challenges!r}")
    pass_challenges = [r["message"].get("challenges") for r in mine
                       if r["message"]["eventId"] in passes and r["message"].get("eventResponse") == "Pass"]
    assert all("Password:Success" in (c or []) for c in pass_challenges), (
        f"the successful attempt's records do not carry Password:Success: {pass_challenges!r}")

    # Phase 2: clear the pool's delivery, sign in as 'quiet', then sign in on the CONTROL pool.
    # The control record arriving bounds the wait for the absence instead of a sleep.
    _retry_throttled(lambda: idp.set_log_delivery_configuration(UserPoolId=pool, LogConfigurations=[]))
    cleared = idp.get_log_delivery_configuration(UserPoolId=pool)["LogDeliveryConfiguration"]
    assert cleared.get("LogConfigurations", []) == [], f"delivery not cleared: {cleared!r}"
    _sign_in(idp, client, quiet)
    _sign_in(idp, ctrl_client, ctrl)
    _await(logs, group, _passed(ctrl[0], ctrl_pool), "the control pool's sign-in record (barrier 1)")

    # Phase 3: restore the delivery, sign in as 'repair'; it must arrive (barrier 2, loop closed).
    _set_delivery(idp, pool, group_arn)
    _sign_in(idp, client, repair)
    recs = _await(logs, group, _passed(repair[0], pool), "the restored pool's 'repair' sign-in record")
    leaked = [r for r in recs if r["message"].get("userName") == quiet[0]]
    assert leaked == [], (
        f"{len(leaked)} record(s) for the sign-in made while delivery was CLEARED reached the "
        f"log group: {leaked[:2]!r}")


def _audited_pool(ctx, idp, prefix: str) -> tuple[str, str]:
    pool = _retry_throttled(lambda: idp.create_user_pool(
        PoolName=ctx.unique_name(prefix),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags=_TAGS,
    ))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool))
    desc = idp.describe_user_pool(UserPoolId=pool)["UserPool"]
    assert desc.get("UserPoolTier") == "PLUS", f"pool tier {desc.get('UserPoolTier')!r}"
    mode = (desc.get("UserPoolAddOns") or {}).get("AdvancedSecurityMode")
    assert mode == "AUDIT", f"AdvancedSecurityMode {mode!r}, expected 'AUDIT'"
    client = _retry_throttled(lambda: idp.create_user_pool_client(
        UserPoolId=pool, ClientName="sim2real-xsvc-sat",
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    ))["UserPoolClient"]["ClientId"]
    return pool, client


def _set_delivery(idp, pool: str, arn: str) -> None:
    _retry_throttled(lambda: idp.set_log_delivery_configuration(UserPoolId=pool, LogConfigurations=[{
        "EventSource": "userAuthEvents", "LogLevel": "INFO",
        "CloudWatchLogsConfiguration": {"LogGroupArn": arn}}]))
    got = idp.get_log_delivery_configuration(UserPoolId=pool)["LogDeliveryConfiguration"]["LogConfigurations"]
    assert [c["CloudWatchLogsConfiguration"]["LogGroupArn"] for c in got] == [arn], f"delivery read back {got!r}"


def _user(ctx, idp, pool: str, prefix: str) -> tuple[str, str]:
    name = ctx.unique_name(prefix).lower()
    password = "Aa1!" + secrets.token_hex(10)
    _retry_throttled(lambda: idp.admin_create_user(UserPoolId=pool, Username=name, MessageAction="SUPPRESS"))
    _retry_throttled(lambda: idp.admin_set_user_password(
        UserPoolId=pool, Username=name, Password=password, Permanent=True))
    return name, password


def _sign_in(idp, client: str, user: tuple[str, str]) -> dict:
    return _retry_throttled(lambda: idp.initiate_auth(
        ClientId=client, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user[0], "PASSWORD": user[1]}))


def _passed(username: str, pool: str):
    def done(recs):
        hit = [r for r in recs if r["message"].get("userName") == username
               and r["message"].get("userPoolId") == pool and r["message"].get("eventResponse") == "Pass"]
        return bool(hit), recs
    return done


# CloudWatch Logs' vended-delivery machinery (not Cognito) writes one plain-text line,
# "Permissions are set correctly to allow AWS CloudWatch Logs to write into your logs while
# creating a subscription.", into this fixed stream when a delivery subscription is attached.
# It is the only stream excluded; every other event must be a structured Cognito record.
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"


def _records(logs, group: str) -> list:
    out, kw = [], {"logGroupName": group}
    while True:
        page = logs.filter_log_events(**kw)
        for e in page.get("events", []):
            if e.get("logStreamName") == _VALIDATION_STREAM:
                continue
            try:
                rec = json.loads(e["message"])
            except ValueError:
                raise AssertionError(
                    f"non-JSON event in stream {e.get('logStreamName')!r}: {e['message'][:300]!r}") from None
            assert isinstance(rec, dict) and isinstance(rec.get("message"), dict), (
                f"unstructured record {e['message'][:300]!r}")
            out.append(rec)
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


def _await(logs, group: str, cond, what: str):
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    recs = []
    while time.monotonic() < deadline:
        recs = _records(logs, group)
        done, value = cond(recs)
        if done:
            return value
        time.sleep(_POLL_S)
    raise AssertionError(
        f"{what} did not reach {group!r} within {_DELIVERY_BUDGET_S}s; "
        f"{len(recs)} record(s) present: {[r['message'].get('userName') for r in recs]!r}")


def _all_groups(logs, prefix: str) -> list:
    out, kw = [], {"logGroupNamePrefix": prefix}
    while True:
        page = logs.describe_log_groups(**kw)
        out.extend(page.get("logGroups", []))
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message), raising if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_throttled(fn, *, attempts: int = 8):
    delay = 1.0
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TooManyRequestsException" and i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
