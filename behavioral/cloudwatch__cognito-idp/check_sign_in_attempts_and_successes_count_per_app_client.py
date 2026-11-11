"""sign-in-attempts-and-successes-count-per-app-client."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sign-in-attempts-and-successes-count-per-app-client"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "cognito-idp"]

_N_SUCCESSES = 4
_N_FAILURES = 3

_METRIC_CAP_S = 420.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/cognito/latest/developerguide/metrics-for-cognito-user-pools.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """AWS/Cognito SignInSuccesses per (UserPool, UserPoolClient) counts every sign-in request as a
    sample and only the successful ones in its Sum, with no unit; a second client on the same pool
    publishes nothing until it is signed in through, then counts only its own sign-in.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/metrics-for-cognito-user-pools.html
    """
    idp = ctx.client("cognito-idp")
    cw = ctx.client("cloudwatch")

    pool_id = _user_pool(ctx, idp)
    used_client = _app_client(ctx, idp, pool_id, "used-")
    idle_client = _app_client(ctx, idp, pool_id, "idle-")

    username = ctx.unique_name("sim2real-cwcog-user-")
    password = "Sim2Real!" + ctx.unique_name("Pw")[-12:]
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.invalid"}],
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", (
        f"user {username} is in status {status!r} after AdminSetUserPassword(Permanent=True), "
        f"expected 'CONFIRMED'"
    )
    window_start = datetime.now(timezone.utc) - timedelta(minutes=10)

    # Refusals first, so every failed sample is sent before any success can be published.
    for i in range(_N_FAILURES):
        try:
            bad = idp.initiate_auth(
                ClientId=used_client,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password + "-wrong"},
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            assert code == "NotAuthorizedException", (
                f"failed sign-in {i + 1} of {_N_FAILURES} was refused with {code!r}, expected "
                f"'NotAuthorizedException'"
            )
            assert message == "Incorrect username or password.", (
                f"expected the exact NotAuthorizedException message AWS returns, got {message!r}"
            )
        else:
            raise AssertionError(
                f"failed sign-in {i + 1} of {_N_FAILURES} SUCCEEDED with a wrong password: {bad!r}"
            )

    for i in range(_N_SUCCESSES):
        _sign_in(idp, used_client, username, password, f"sign-in {i + 1} of {_N_SUCCESSES}")

    def _stats(client_id: str) -> tuple[float, float] | None:
        """(Sum, SampleCount) of SignInSuccesses for one client over the window, or None."""
        dps = _datapoints(cw, pool_id, client_id, window_start)
        if not dps:
            return None
        return (float(sum(d["Sum"] for d in dps)), float(sum(d["SampleCount"] for d in dps)))

    want_used = (float(_N_SUCCESSES), float(_N_SUCCESSES + _N_FAILURES))
    # Every request is a sample (1 for a success, 0 for a failure), so once all of them are
    # counted the Sum is final; no stability window is needed.
    used = _poll_until(
        ctx, lambda: _stats(used_client),
        lambda s: s is not None and s[1] >= want_used[1],
        cap_s=_METRIC_CAP_S, interval_s=5.0,
        description=f"SignInSuccesses for UserPoolClient={used_client} counting "
                    f"{_N_SUCCESSES + _N_FAILURES} samples")
    assert used == want_used, (
        f"SignInSuccesses (Sum, SampleCount) for UserPoolClient={used_client} is {used!r}; this "
        f"check made {_N_SUCCESSES} successful and {_N_FAILURES} refused sign-ins, so AWS reports "
        f"{want_used!r}"
    )
    units = {d.get("Unit") for d in _datapoints(cw, pool_id, used_client, window_start)}
    assert units == {"None"}, (
        f"SignInSuccesses datapoints for UserPoolClient={used_client} carry Unit(s) {units!r}, "
        f"expected exactly {{'None'}}"
    )
    idle_before = _stats(idle_client)
    assert idle_before is None, (
        f"the idle client {idle_client} on the same pool, never signed in through, reads "
        f"{idle_before!r} while the used client already reads {used!r}"
    )

    # Positive control after the absence: one sign-in through the idle client counts for it alone.
    _sign_in(idp, idle_client, username, password, "the idle client's sign-in")
    idle = _poll_until(
        ctx, lambda: _stats(idle_client), lambda s: s is not None and s[1] >= 1.0,
        cap_s=_METRIC_CAP_S, interval_s=5.0,
        description=f"SignInSuccesses for UserPoolClient={idle_client} counting its sign-in")
    assert idle == (1.0, 1.0), (
        f"the idle client's single sign-in reads (Sum, SampleCount) {idle!r}, expected (1.0, 1.0); "
        f"a pool-wide total served under each client id would read more"
    )
    final = _stats(used_client)
    assert final == want_used, (
        f"the idle client's sign-in changed the used client's series to {final!r}"
    )

    sets = _poll_until(
        ctx, lambda: _dimension_sets(cw, "AWS/Cognito", "UserPool", pool_id),
        lambda s: ("UserPool", "UserPoolClient") in s,
        cap_s=_METRIC_CAP_S, interval_s=5.0,
        description=f"ListMetrics listing the (UserPool, UserPoolClient) series for {pool_id}")
    assert ("UserPool", "UserPoolClient") in sets, f"ListMetrics dimension sets {sorted(sets)!r}"


# ===== helpers =====
def _sign_in(idp, client_id: str, username: str, password: str, what: str) -> None:
    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert resp.get("AuthenticationResult", {}).get("AccessToken"), (
        f"{what} returned no AccessToken (challenge {resp.get('ChallengeName')!r}): {resp!r}"
    )


def _datapoints(cw, pool_id: str, client_id: str, since: datetime) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Cognito",
        MetricName="SignInSuccesses",
        Dimensions=[
            {"Name": "UserPool", "Value": pool_id},
            {"Name": "UserPoolClient", "Value": client_id},
        ],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=10),
        Period=300,
        Statistics=["Sum", "SampleCount"],
    )["Datapoints"]


def _user_pool(ctx, idp) -> str:
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cwcog-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real": "cloudwatch__cognito-idp", "sim2real-check": CHECK},
    )["UserPool"]["Id"]

    def _delete() -> None:
        # DeleteUserPool removes its app clients and users, so one cleanup covers the whole tree.
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    return pool_id


def _app_client(ctx, idp, pool_id: str, label: str) -> str:
    return idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name(f"sim2real-cwcog-{label}"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, cap_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) holds and return it; a wait the run budget ended
    raises TimeoutError (not graded), one that ran out its own cap fails."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget ended while waiting for {description}; last {last!r}")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s; last {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
