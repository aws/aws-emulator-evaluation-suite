"""thirty-way-concurrency-creates-thirty-distinct-environments."""

from __future__ import annotations

import concurrent.futures
import datetime
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "thirty-way-concurrency-creates-thirty-distinct-environments"
GROUP = 'concurrency'
SERVICES = ['lambda']

WIDTH = 30          # the reservation, and the width of the first two bursts
OVER = 40           # the over-burst, 10 wider than the reservation
HOLD_S = 20         # long enough that all WIDTH invocations are in flight together

ENV_PROBE = """\
import json
import os
import time
import uuid

ENV_ID = str(uuid.uuid4())
INIT_PID = os.getpid()
INIT_EPOCH = time.time()
INIT_COUNT = 0
INIT_COUNT += 1
INVOKE_COUNT = 0


def handler(event, context):
    global INVOKE_COUNT
    INVOKE_COUNT += 1
    time.sleep(float(event.get("hold_s", 0)))
    return {
        "env_id": ENV_ID,
        "init_pid": INIT_PID,
        "invoke_pid": os.getpid(),
        "init_epoch": INIT_EPOCH,
        "init_count": INIT_COUNT,
        "invoke_count": INVOKE_COUNT,
        "log_stream": context.log_stream_name,
        "request_id": context.aws_request_id,
        }
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


_ROLES: dict = {}


def _exec_role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_when_role_ready(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the check's remaining time so it fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _wait_ready(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active in {timeout_s}s; last={last!r}")


def _burst(lam, fn, n, hold_s):
    """n simultaneous RequestResponse invokes. Returns (bodies, throttles).

    A throttled call is captured rather than raised so the over-burst arm can assert on the
    exact error, and an unexpected error is re-raised so it can never be mistaken for one.
    """
    def _one(_i):
        try:
            resp = lam.invoke(
                FunctionName=fn, InvocationType="RequestResponse",
                Payload=json.dumps({"hold_s": hold_s}).encode(),
            )
        except ClientError as exc:
            return {"error": exc.response}
        raw = resp["Payload"].read()
        if resp.get("FunctionError"):
            raise AssertionError(
                f"{fn} returned FunctionError={resp['FunctionError']!r}: {raw[:400]!r}"
            )
        assert raw, f"{fn} returned an empty payload: {resp!r}"
        return {"body": json.loads(raw)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_one, range(n)))
    return ([r["body"] for r in results if "body" in r],
            [r["error"] for r in results if "error" in r])


def _multimaps(bodies):
    fwd, rev = {}, {}
    for b in bodies:
        fwd.setdefault(b["env_id"], set()).add(b["log_stream"])
        rev.setdefault(b["log_stream"], set()).add(b["env_id"])
    return fwd, rev


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-concurrency.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """30 simultaneous invocations run in exactly 30 fresh environments, a second burst reuses all
    of them, ConcurrentExecutions peaks at 30, a 40-wide burst is throttled down to the reservation
    (ReservedFunctionConcurrentInvocationLimitExceeded), and the deleted function is gone.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html
    """
    lam = ctx.client("lambda")
    # A widened pool (botocore's default of 10 would serialise a 30-wide burst into 10 sockets and
    # quietly turn this into a 10-way check) and no retries (so an over-burst throttle surfaces to
    # the caller instead of being absorbed).
    burst_client = ctx.client(
        "lambda",
        config=Config(max_pool_connections=64, read_timeout=180,
                      retries={"max_attempts": 0, "mode": "standard"}),
    )
    cw = ctx.client("cloudwatch")

    settings = lam.get_account_settings()["AccountLimit"]
    assert settings["UnreservedConcurrentExecutions"] >= WIDTH + 100, (
        f"this account cannot host a {WIDTH}-wide reservation: "
        f"UnreservedConcurrentExecutions={settings['UnreservedConcurrentExecutions']!r} of "
        f"ConcurrentExecutions={settings['ConcurrentExecutions']!r}, and Lambda requires 100 to "
        f"remain unreserved"
    )

    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function_when_role_ready(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(ENV_PROBE)},
        MemorySize=512, Timeout=120,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_ready(lam, fn, _budget(ctx, 120.0))

    conc = lam.put_function_concurrency(
        FunctionName=fn, ReservedConcurrentExecutions=WIDTH
    )
    assert conc["ReservedConcurrentExecutions"] == WIDTH, conc

    window_start = datetime.datetime.now(datetime.timezone.utc)
    burst1, throttled1 = _burst(burst_client, fn, WIDTH, HOLD_S)
    assert not throttled1, (
        f"a {WIDTH}-wide burst against ReservedConcurrentExecutions={WIDTH} must not be "
        f"throttled, got {len(throttled1)} rejections: "
        f"{[e.get('Error', {}).get('Code') for e in throttled1]!r}"
    )
    assert len(burst1) == WIDTH, f"expected {WIDTH} responses, got {len(burst1)}"

    # (1) thirty environments, exactly.
    envs1 = {b["env_id"] for b in burst1}
    assert len(envs1) == WIDTH, (
        f"{WIDTH} simultaneous invocations must be served by {WIDTH} distinct execution "
        f"environments, got {len(envs1)}: {sorted(envs1)!r}"
    )
    # (2) each is a fresh environment on its first invocation.
    assert all(b["init_count"] == 1 for b in burst1), (
        f"init must run exactly once per environment, got "
        f"{sorted({b['init_count'] for b in burst1})!r}"
    )
    assert all(b["invoke_count"] == 1 for b in burst1), (
        f"every environment in the first burst must be on its first invocation, got "
        f"{sorted(b['invoke_count'] for b in burst1)!r}"
    )
    # (3) the env<->stream bijection at |E|=30.
    streams1 = {b["log_stream"] for b in burst1}
    assert len(streams1) == WIDTH, (
        f"{WIDTH} environments must own {WIDTH} log streams, got {len(streams1)}: "
        f"{sorted(streams1)!r}"
    )
    fwd, rev = _multimaps(burst1)
    bad_fwd = {e: s for e, s in fwd.items() if len(s) != 1}
    bad_rev = {s: e for s, e in rev.items() if len(e) != 1}
    assert not bad_fwd, f"an env_id reported several log streams: {bad_fwd!r}"
    assert not bad_rev, f"a log stream was reported by several env_ids: {bad_rev!r}"
    # (4) thirty genuinely distinct invocations.
    assert len({b["request_id"] for b in burst1}) == WIDTH, (
        f"expected {WIDTH} distinct aws_request_ids, got "
        f"{len({b['request_id'] for b in burst1})}"
    )

    # Act 2 — the pool now holds WIDTH warm environments, so this burst must be served from them.
    # It is held as long as burst 1, so no environment finishes and takes a second call of it.
    burst2, throttled2 = _burst(burst_client, fn, WIDTH, HOLD_S)
    assert not throttled2, (
        f"the second {WIDTH}-wide burst must not be throttled, got {len(throttled2)}"
    )
    assert len(burst2) == WIDTH, f"expected {WIDTH} responses, got {len(burst2)}"
    envs2 = {b["env_id"] for b in burst2}
    # (5) THE NEGATIVE SPACE: no environment outside the known set was created.
    assert envs2.issubset(envs1), (
        f"the second burst created execution environments outside the warm pool: "
        f"{sorted(envs2 - envs1)!r} are not among the {WIDTH} from the first burst"
    )
    # (6) and the reuse was one-to-one, not WIDTH invocations funnelled into a few environments.
    assert len(envs2) == WIDTH, (
        f"the second burst must draw on all {WIDTH} warm environments, got {len(envs2)}: "
        f"{sorted(envs2)!r}"
    )
    # (7) each reused environment is on its second invocation and did not re-init.
    assert all(b["invoke_count"] == 2 for b in burst2), (
        f"every reused environment must report invoke_count == 2, got "
        f"{sorted(b['invoke_count'] for b in burst2)!r}"
    )
    assert all(b["init_count"] == 1 for b in burst2), (
        f"a reused environment must not re-run init, got "
        f"{sorted({b['init_count'] for b in burst2})!r}"
    )

    # Act 3 — the over-burst. The reservation is a ceiling on environments, not only on requests.
    over, throttled = _burst(burst_client, fn, OVER, HOLD_S)
    # (8) the ceiling is real, and admission is not "throttle everything".
    assert len(over) <= WIDTH, (
        f"a {OVER}-wide burst against ReservedConcurrentExecutions={WIDTH} admitted "
        f"{len(over)} invocations — the reservation is not enforced"
    )
    assert len(over) >= WIDTH - 5, (
        f"only {len(over)} of {OVER} invocations were admitted against a reservation of "
        f"{WIDTH}; admission control is rejecting work that has a slot"
    )
    # (9) every non-admitted call was a throttle, not a hang or a 500.
    assert len(throttled) == OVER - len(over), (
        f"{OVER} calls produced {len(over)} responses and {len(throttled)} errors, which do not "
        f"account for every invocation"
    )
    codes = [e.get("Error", {}).get("Code") for e in throttled]
    assert all(c == "TooManyRequestsException" for c in codes), (
        f"an over-burst must be rejected with TooManyRequestsException, got {codes!r}"
    )
    messages = [e.get("Error", {}).get("Message") for e in throttled]
    assert all(m == "Rate Exceeded." for m in messages), (
        f"unexpected reserved-concurrency throttle message, got {sorted(set(map(str, messages)))!r}"
    )
    reasons = [e.get("Reason") for e in throttled]
    assert all(r == "ReservedFunctionConcurrentInvocationLimitExceeded" for r in reasons), (
        f"a reserved-concurrency throttle must carry Reason="
        f"ReservedFunctionConcurrentInvocationLimitExceeded, distinguishing it from the "
        f"account-limit reason; got {reasons!r}"
    )
    statuses = [e.get("ResponseMetadata", {}).get("HTTPStatusCode") for e in throttled]
    assert all(s == 429 for s in statuses), (
        f"a throttle is HTTP 429, got {statuses!r}"
    )
    err_types = [e.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amzn-errortype")
                 for e in throttled]
    assert all(t == "TooManyRequestsException" for t in err_types), (
        f"the x-amzn-errortype header must name the throttle, got {err_types!r}"
    )
    # (10) effect-absent for the rejected calls: they created no execution environment, so the
    # environment set is still capped at WIDTH and drawn from the known pool.
    envs3 = {b["env_id"] for b in over}
    assert len(envs3) <= WIDTH, (
        f"the over-burst produced {len(envs3)} environments against a reservation of {WIDTH}: "
        f"{sorted(envs3)!r}"
    )
    assert envs3.issubset(envs1), (
        f"the over-burst created environments outside the reserved pool: "
        f"{sorted(envs3 - envs1)!r}"
    )
    window_end = datetime.datetime.now(datetime.timezone.utc)

    # Act 4 — CloudWatch must agree with the environment count. Bounded poll for publication;
    # it ends in a failure, never a skip.
    metric_wait_s = _budget(ctx, 300.0)
    deadline = time.monotonic() + metric_wait_s
    values = []
    while time.monotonic() < deadline:
        got = cw.get_metric_data(
            MetricDataQueries=[{
                "Id": "conc",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": "ConcurrentExecutions",
                        "Dimensions": [{"Name": "FunctionName", "Value": fn}],
                    },
                    "Period": 60,
                    "Stat": "Maximum",
                },
            }],
            StartTime=window_start - datetime.timedelta(minutes=2),
            EndTime=window_end + datetime.timedelta(minutes=2),
        )["MetricDataResults"][0]
        values = got["Values"]
        # A minute's datapoint can first publish before every sample is aggregated into it.
        if values and max(values) >= WIDTH:
            break
        time.sleep(2)
    assert values, (
        f"AWS/Lambda ConcurrentExecutions published no datapoint for {fn} within "
        f"{metric_wait_s:.0f}s of a {WIDTH}-wide burst; the metric must be derived from actual "
        f"in-flight execution"
    )
    peak = max(values)
    # (11) the metric agrees with the environment count in both directions: it saw the burst, and
    # it is a concurrency gauge rather than a request counter (which would report 100 here).
    assert peak >= WIDTH, (
        f"ConcurrentExecutions peaked at {peak!r} while {WIDTH} invocations were in "
        f"flight together; datapoints were {values!r}"
    )
    assert peak <= WIDTH, (
        f"ConcurrentExecutions peaked at {peak!r}, above the hard reservation of {WIDTH} — the "
        f"metric is counting requests ({OVER + 2 * WIDTH} were issued) rather than concurrent "
        f"executions; datapoints were {values!r}"
    )

    # Act 5 — deleted must mean gone, and unusable, at an independent read.
    lam.delete_function(FunctionName=fn)
    not_found = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    try:
        lam.get_function_configuration(FunctionName=fn)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"a read of a deleted function must fail ResourceNotFoundException, got "
            f"{exc.response['Error']!r}"
        )
        assert exc.response["Error"].get("Message") == not_found, (
            f"unexpected not-found message for a deleted function, got {exc.response['Error']!r}"
        )
    else:
        raise AssertionError(f"{fn} still resolves after delete_function")
    # The invoke path converges on the delete a few seconds after the control plane does, so the
    # unusable leg is a bounded poll that ends in a failure, never a pass on a lingering invoke.
    invoke_wait_s = _budget(ctx, 120.0)
    invoke_deadline = time.monotonic() + invoke_wait_s
    while True:
        try:
            lam.invoke(FunctionName=fn, Payload=b"{}")
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
                f"an invoke of a deleted function must fail ResourceNotFoundException, got "
                f"{exc.response['Error']!r}"
            )
            assert exc.response["Error"].get("Message") == f"{not_found}:$LATEST", (
                f"unexpected not-found message invoking a deleted function, got {exc.response['Error']!r}"
            )
            break
        if time.monotonic() > invoke_deadline:
            raise AssertionError(
                f"{fn} is still invocable {invoke_wait_s:.0f}s after delete_function"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
