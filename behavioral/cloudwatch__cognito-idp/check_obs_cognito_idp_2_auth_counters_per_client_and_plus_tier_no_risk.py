"""obs-cognito-idp-2-auth-counters-per-client-and-plus-tier-no-risk."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-idp-2-auth-counters-per-client-and-plus-tier-no-risk"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "cognito-idp"]

_GOOD_SIGN_INS = 2
_BAD_SIGN_INS = 3
_REFRESHES = 2
_SIGN_UPS = 1

#: Per-series ceiling. A series that has not settled inside it is a FAIL, never a dropped leg.
_SERIES_BUDGET_S = 900.0
_POLL_S = 2.0
#: ListMetrics' catalogue index lags GetMetricStatistics; a series already readable as a statistic
#: can still be briefly unlisted.
_LISTMETRICS_BUDGET_S = 600.0
_LISTMETRICS_POLL_S = 10.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:happy-path",
    # c2: the subject is accumulating per-dimension counters, not declared resource state.
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """Cognito publishes per-app-client SignIn/TokenRefresh/SignUp counters (a refused sign-in is a
    zero-valued sample), nothing for an unused client, and a Plus-tier AUDIT sign-in's NoRisk under
    (Operation, UserPoolId) rather than UserPool.
    """
    idp = ctx.client("cognito-idp")
    cw = ctx.client("cloudwatch")
    password = "Sim2Real!" + ctx.unique_name("Pw")[-12:]

    pool = _user_pool(ctx, idp, "sim2real-xsvc-obs2-")
    client_a = _app_client(ctx, idp, pool, "a-")
    client_b = _app_client(ctx, idp, pool, "b-")
    user = _confirmed_user(ctx, idp, pool, password)

    refresh_tokens = []
    for i in range(_GOOD_SIGN_INS):
        resp = idp.initiate_auth(
            ClientId=client_a,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user, "PASSWORD": password},
        )
        result = resp.get("AuthenticationResult") or {}
        assert result.get("AccessToken") and result.get("RefreshToken"), (
            f"good sign-in {i + 1}/{_GOOD_SIGN_INS} on client A returned no AccessToken/RefreshToken "
            f"(challenge {resp.get('ChallengeName')!r}): {sorted(result)!r}"
        )
        refresh_tokens.append(result["RefreshToken"])

    for i in range(_BAD_SIGN_INS):
        refusal = _error(
            lambda: idp.initiate_auth(
                ClientId=client_a,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": user, "PASSWORD": password + "-wrong"},
            )
        )
        want = ("NotAuthorizedException", "Incorrect username or password.")
        assert refusal == want, (
            f"wrong-password sign-in {i + 1}/{_BAD_SIGN_INS} on client A was refused with {refusal!r}, "
            f"expected {want!r}"
        )

    for i in range(_REFRESHES):
        resp = idp.initiate_auth(
            ClientId=client_a,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_tokens[0]},
        )
        assert (resp.get("AuthenticationResult") or {}).get("AccessToken"), (
            f"refresh {i + 1}/{_REFRESHES} on client A returned no AccessToken: {resp!r}"
        )

    signup_user = ctx.unique_name("sim2real-xsvc-obs2-su-")
    resp = idp.sign_up(
        ClientId=client_a,
        Username=signup_user,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": f"{signup_user}@example.invalid"}],
    )
    assert resp["UserConfirmed"] is False, f"SignUp confirmed the user on its own: {resp!r}"
    idp.admin_confirm_sign_up(UserPoolId=pool, Username=signup_user)
    status = idp.admin_get_user(UserPoolId=pool, Username=signup_user)["UserStatus"]
    assert status == "CONFIRMED", f"signed-up user is {status!r} after AdminConfirmSignUp"

    plus = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-obs2-plus-"),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"},
        UserPoolTags={"sim2real": "cloudwatch__cognito-idp", "sim2real-check": CHECK},
    )["UserPool"]
    plus_pool = plus["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=plus_pool))
    described = idp.describe_user_pool(UserPoolId=plus_pool)["UserPool"]
    assert described.get("UserPoolTier") == "PLUS", (
        f"pool {plus_pool} reports tier {described.get('UserPoolTier')!r}, expected 'PLUS'"
    )
    mode = (described.get("UserPoolAddOns") or {}).get("AdvancedSecurityMode")
    assert mode == "AUDIT", f"pool {plus_pool} reports AdvancedSecurityMode {mode!r}, expected 'AUDIT'"
    plus_client = _app_client(ctx, idp, plus_pool, "plus-")
    plus_user = _confirmed_user(ctx, idp, plus_pool, password)
    resp = idp.initiate_auth(
        ClientId=plus_client,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": plus_user, "PASSWORD": password},
    )
    assert (resp.get("AuthenticationResult") or {}).get("AccessToken"), (
        f"the PLUS/AUDIT pool sign-in returned no AccessToken (AUDIT must not block): {resp!r}"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=20)

    def stats(metric, dims):
        dps = cw.get_metric_statistics(
            Namespace="AWS/Cognito",
            MetricName=metric,
            Dimensions=[{"Name": k, "Value": v} for k, v in dims],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=3600,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]
        if not dps:
            return None
        return (float(sum(d["Sum"] for d in dps)), float(sum(d["SampleCount"] for d in dps)))

    def client_dims(c):
        return (("UserPool", pool), ("UserPoolClient", c))

    risk_by_id = (("Operation", "SignIn"), ("UserPoolId", plus_pool))
    risk_by_pool_key = (("Operation", "SignIn"), ("UserPool", plus_pool))
    present = {
        "A.SignInSuccesses": ("SignInSuccesses", client_dims(client_a)),
        "A.TokenRefreshSuccesses": ("TokenRefreshSuccesses", client_dims(client_a)),
        "A.SignUpSuccesses": ("SignUpSuccesses", client_dims(client_a)),
        "PLUS.NoRisk(Operation,UserPoolId)": ("NoRisk", risk_by_id),
    }
    absent = {
        "B.SignInSuccesses": ("SignInSuccesses", client_dims(client_b)),
        "B.TokenRefreshSuccesses": ("TokenRefreshSuccesses", client_dims(client_b)),
        "B.SignUpSuccesses": ("SignUpSuccesses", client_dims(client_b)),
        "PLUS.NoRisk(Operation,UserPool)": ("NoRisk", risk_by_pool_key),
    }
    # Expected (Sum, SampleCount); None leaves SampleCount ungraded.
    want = {
        "A.SignInSuccesses": (float(_GOOD_SIGN_INS), float(_GOOD_SIGN_INS + _BAD_SIGN_INS)),
        "A.TokenRefreshSuccesses": (float(_REFRESHES), None),
        "A.SignUpSuccesses": (float(_SIGN_UPS), None),
        "PLUS.NoRisk(Operation,UserPoolId)": (1.0, None),
    }
    readings = _poll_all_until_expected(
        ctx,
        {k: (lambda m=m, d=d: stats(m, d)) for k, (m, d) in present.items()},
        want,
        budget_s=_SERIES_BUDGET_S,
        poll_s=_POLL_S,
    )

    def expect(key, want_sum, want_count=None):
        got = readings[key]
        assert got is not None and got[0] == want_sum and (want_count is None or got[1] == want_count), (
            f"{key} settled at (Sum, SampleCount) {got!r}, expected Sum {want_sum!r}"
            + (f" SampleCount {want_count!r}" if want_count is not None else "")
            + f"; all settled readings: {readings!r}"
        )

    # 2 successes + 3 refusals published as zero-valued samples; refresh added nothing to this series;
    # AdminConfirmSignUp adds no SignUpSuccesses.
    expect("A.SignInSuccesses", float(_GOOD_SIGN_INS), float(_GOOD_SIGN_INS + _BAD_SIGN_INS))
    s, n = readings["A.SignInSuccesses"]
    assert abs(s / n - 0.4) < 1e-9, f"SignInSuccesses Average for A is {s / n!r}, expected 0.4"
    expect("A.TokenRefreshSuccesses", float(_REFRESHES))
    expect("A.SignUpSuccesses", float(_SIGN_UPS))
    expect("PLUS.NoRisk(Operation,UserPoolId)", 1.0)

    # Read only after A's series and NoRisk settled, so an absence is not a race. Dimension matching
    # is exact, so the UserPool-keyed NoRisk read shows which key Cognito published.
    for key, (metric, dims) in absent.items():
        got = stats(metric, dims)
        assert got is None, (
            f"{key} has datapoints {got!r}, expected none; settled readings: {readings!r}"
        )

    # The ListMetrics catalogue is indexed separately from GetMetricStatistics and lags it, so a
    # metric already readable as a statistic can still be briefly absent here; poll for it.
    plus_sets = _poll_until_listed(
        lambda: _dimension_sets(cw, "UserPoolId", plus_pool),
        ("NoRisk", ("Operation", "UserPoolId")),
        budget_s=_LISTMETRICS_BUDGET_S,
        poll_s=_LISTMETRICS_POLL_S,
    )
    assert ("NoRisk", ("Operation", "UserPoolId")) in plus_sets, (
        f"ListMetrics for UserPoolId={plus_pool} lists {sorted(plus_sets)!r}; expected NoRisk under "
        f"(Operation, UserPoolId)"
    )
    pool_sets = _poll_until_listed(
        lambda: _dimension_sets(cw, "UserPool", pool),
        ("SignInSuccesses", ("UserPool", "UserPoolClient")),
        budget_s=_LISTMETRICS_BUDGET_S,
        poll_s=_LISTMETRICS_POLL_S,
    )
    assert ("SignInSuccesses", ("UserPool", "UserPoolClient")) in pool_sets, (
        f"ListMetrics for UserPool={pool} lists {sorted(pool_sets)!r}; expected SignInSuccesses under "
        f"(UserPool, UserPoolClient)"
    )
    assert not any(m == "NoRisk" for m, _ in _dimension_sets(cw, "UserPool", plus_pool)), (
        f"ListMetrics lists NoRisk under a UserPool={plus_pool} dimension set; Cognito's risk metrics "
        f"dimension on UserPoolId"
    )

    # Positive control after the absence reads: A's sign-in series is unchanged.
    final = stats("SignInSuccesses", client_dims(client_a))
    assert final == readings["A.SignInSuccesses"], (
        f"A.SignInSuccesses moved from {readings['A.SignInSuccesses']!r} to {final!r} after settling"
    )
    print(f"[{CHECK}] settled readings: {readings!r}")


def _user_pool(ctx, idp, prefix: str) -> str:
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name(prefix),
        UserPoolTags={"sim2real": "cloudwatch__cognito-idp", "sim2real-check": CHECK},
    )["UserPool"]["Id"]
    # DeleteUserPool removes its app clients and users, so one cleanup covers the whole tree.
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _app_client(ctx, idp, pool_id: str, label: str) -> str:
    # No separate cleanup: the pool's DeleteUserPool (registered at pool create) removes the client.
    return idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name(f"sim2real-xsvc-obs2-{label}"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]


def _confirmed_user(ctx, idp, pool_id: str, password: str) -> str:
    username = ctx.unique_name("sim2real-xsvc-obs2-u-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.invalid"}],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"user {username} is {status!r} after AdminSetUserPassword(Permanent)"
    return username


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; raises if fn() succeeds."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"call expected to be refused SUCCEEDED: {out!r}")


def _poll_until_listed(probe, member: tuple, *, budget_s: float, poll_s: float) -> set:
    """Poll a ListMetrics-backed set until it contains member, never past budget_s."""
    deadline = time.monotonic() + budget_s
    while True:
        seen = probe()
        if member in seen or time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _dimension_sets(cw, dim_name: str, dim_value: str) -> set:
    seen = set()
    token = None
    while True:
        kwargs = {"Namespace": "AWS/Cognito", "Dimensions": [{"Name": dim_name, "Value": dim_value}]}
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add((m["MetricName"], tuple(sorted(d["Name"] for d in m["Dimensions"]))))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_all_until_expected(ctx, probes: dict, want: dict, *, budget_s: float, poll_s: float) -> dict:
    """Poll every probe together until each reads its expected (Sum, SampleCount), then re-read
    once: a series still moving after reaching its value has not settled."""
    left = ctx.time_left()
    deadline = time.monotonic() + (budget_s if left is None else min(budget_s, left))

    def matches(got, expected) -> bool:
        return got is not None and got[0] == expected[0] and expected[1] in (None, got[1])

    while True:
        last = {key: probe() for key, probe in probes.items()}
        if all(matches(last[k], want[k]) for k in probes):
            again = {key: probe() for key, probe in probes.items()}
            assert again == last, (
                f"AWS/Cognito series moved after reaching their expected values: {last!r} -> {again!r}"
            )
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"not every AWS/Cognito series reached its expected (Sum, SampleCount) {want!r} "
                f"within {budget_s}s; last readings {last!r}"
            )
        time.sleep(poll_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
