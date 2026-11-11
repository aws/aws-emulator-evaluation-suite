"""obs-cognito-idp-2-sign-in-rejected-for-disabled-flow-is-a-zero-sample."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-idp-2-sign-in-rejected-for-disabled-flow-is-a-zero-sample"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "cognito-idp"]

_REJECTED = 3
_SERIES_BUDGET_S = 900.0
_POLL_S = 2.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/cognito/latest/developerguide/metrics-for-cognito-user-pools.html
@tags(
    "axis:rejection",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Three correct-password USER_PASSWORD_AUTH sign-ins on a client lacking that flow are refused,
    then the client is repaired and one sign-in succeeds; SignInSuccesses reads Sum 1, SampleCount 4
    (each flow-rejected attempt is a zero-valued sample), and one more success moves it to exactly 2, 5.
    """
    idp = ctx.client("cognito-idp")
    cw = ctx.client("cloudwatch")
    password = "Sim2Real!" + ctx.unique_name("Pw")[-12:]

    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-obs2n-"),
        UserPoolTags={"sim2real": "cloudwatch__cognito-idp", "sim2real-check": CHECK},
    )["UserPool"]["Id"]
    # DeleteUserPool removes its app clients and users, so one cleanup covers the whole tree.
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool))
    client_name = ctx.unique_name("sim2real-xsvc-obs2n-c-")
    client = idp.create_user_pool_client(
        UserPoolId=pool,
        ClientName=client_name,
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"],
    )["UserPoolClient"]["ClientId"]

    user = ctx.unique_name("sim2real-xsvc-obs2n-u-")
    idp.admin_create_user(
        UserPoolId=pool,
        Username=user,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{user}@example.invalid"}],
    )
    idp.admin_set_user_password(UserPoolId=pool, Username=user, Password=password, Permanent=True)
    status = idp.admin_get_user(UserPoolId=pool, Username=user)["UserStatus"]
    assert status == "CONFIRMED", f"user {user} is {status!r} after AdminSetUserPassword(Permanent)"

    def password_auth():
        return idp.initiate_auth(
            ClientId=client,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user, "PASSWORD": password},
        )

    for i in range(_REJECTED):
        refusal = _error(password_auth)
        want = ("InvalidParameterException", "USER_PASSWORD_AUTH flow not enabled for this client")
        assert refusal == want, (
            f"USER_PASSWORD_AUTH attempt {i + 1}/{_REJECTED} on a client that does not allow the flow "
            f"was refused with {refusal!r}, expected {want!r}"
        )

    idp.update_user_pool_client(
        UserPoolId=pool,
        ClientId=client,
        ClientName=client_name,
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
    )
    flows = idp.describe_user_pool_client(UserPoolId=pool, ClientId=client)["UserPoolClient"][
        "ExplicitAuthFlows"
    ]
    assert "ALLOW_USER_PASSWORD_AUTH" in flows, f"client update did not take: {flows!r}"
    resp = password_auth()
    assert (resp.get("AuthenticationResult") or {}).get("AccessToken"), (
        f"sign-in after allowing USER_PASSWORD_AUTH returned no AccessToken: {resp!r}"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=20)

    def series():
        dps = cw.get_metric_statistics(
            Namespace="AWS/Cognito",
            MetricName="SignInSuccesses",
            Dimensions=[
                {"Name": "UserPool", "Value": pool},
                {"Name": "UserPoolClient", "Value": client},
            ],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=3600,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]
        if not dps:
            return None
        return (float(sum(d["Sum"] for d in dps)), float(sum(d["SampleCount"] for d in dps)))

    def reached(sum_at_least, count_at_least):
        return lambda v: v is not None and v[0] >= sum_at_least and v[1] >= count_at_least

    settled = _poll_until(
        series, reached(1.0, _REJECTED + 1), timeout_s=_budget_s(ctx, _SERIES_BUDGET_S), ctx=ctx,
        description="SignInSuccesses shows the repaired sign-in and every earlier attempt",
    )
    print(f"[{CHECK}] settled (Sum, SampleCount): {settled!r}")
    assert settled == (1.0, float(_REJECTED + 1)), (
        f"SignInSuccesses for UserPool={pool} UserPoolClient={client} settled at (Sum, SampleCount) "
        f"{settled!r}, expected {(1.0, float(_REJECTED + 1))!r}: each of the {_REJECTED} flow-rejected "
        f"attempts is a zero-valued sample and the one repaired sign-in is the only success"
    )

    # Positive control ordered after every earlier sample: once a second success is visible, the
    # series holds exactly one more sample, so no late sample for the earlier attempts arrived.
    resp = password_auth()
    assert (resp.get("AuthenticationResult") or {}).get("AccessToken"), (
        f"the control sign-in returned no AccessToken: {resp!r}"
    )
    after = _poll_until(
        series, reached(2.0, _REJECTED + 2), timeout_s=_budget_s(ctx, _SERIES_BUDGET_S), ctx=ctx,
        description="SignInSuccesses shows the control sign-in",
    )
    print(f"[{CHECK}] after the control sign-in (Sum, SampleCount): {after!r}")
    assert after == (2.0, float(_REJECTED + 2)), (
        f"SignInSuccesses for UserPool={pool} UserPoolClient={client} read {after!r} after one more "
        f"success, expected {(2.0, float(_REJECTED + 2))!r}: the series gained samples beyond the "
        f"control sign-in"
    )


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; raises if fn() succeeds."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"call expected to be refused SUCCEEDED: {out!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s: float, description: str, ctx=None):
    """Poll probe() every _POLL_S until predicate() holds; RAISE on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description}: not met within {timeout_s}s; last reading {last!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
