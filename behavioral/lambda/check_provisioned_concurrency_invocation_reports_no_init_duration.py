"""provisioned-concurrency-invocation-reports-no-init-duration."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "provisioned-concurrency-invocation-reports-no-init-duration"
GROUP = 'concurrency'
SERVICES = ['lambda']

# A deliberately slow module scope, so an init that DID happen inside the invocation is
# unmistakable in the REPORT accounting rather than a sub-millisecond rounding artifact.
HANDLER = """\
import time

_T0 = time.time()
_ACC = 0
for _i in range(3_000_000):
    _ACC += _i
INIT_MS = (time.time() - _T0) * 1000.0


def handler(event, context):
    return {"init_ms": INIT_MS, "acc": _ACC}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


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


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=180):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _report_line(resp):
    """The single REPORT line of an Invoke(LogType='Tail') response, and the whole tail.

    Not a substring test over the tail: a provisioned init also emits an 'INIT_REPORT' line.
    """
    tail = base64.b64decode(resp["LogResult"]).decode()
    lines = [ln for ln in tail.splitlines() if ln.startswith("REPORT RequestId:")]
    assert len(lines) == 1, (
        f"expected exactly one REPORT line in the tail log, got {lines!r} (whole tail: {tail!r})"
    )
    return lines[0], tail


def _invoke_tail(lam, target):
    resp = lam.invoke(FunctionName=target, LogType="Tail", Payload=b"{}")
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{target}: StatusCode {resp['StatusCode']!r} {raw!r}"
    assert "FunctionError" not in resp, (
        f"{target} failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
    )
    return _report_line(resp)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A READY provisioned-concurrency version's REPORT line carries no Init Duration (the init is on a
    separate INIT_REPORT line), while a cold $LATEST invocation's REPORT does and a warm one does not.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-pcfn-")
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=512, Timeout=60,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    # ---- control leg FIRST: nothing has invoked $LATEST yet, so this really is cold ----
    cold_report, cold_tail = _invoke_tail(lam, fn)
    assert "Init Duration" in cold_report, (
        f"the first-ever invocation of $LATEST reported no Init Duration, so the control leg "
        f"proves nothing and the comparison below is empty: {cold_report!r}"
    )

    version = lam.publish_version(FunctionName=fn)["Version"]
    qualified = f"{fn}:{version}"
    _wait_active(lam, qualified)

    # Provisioned concurrency BILLS FROM THE MOMENT IT IS READY, so the delete is registered
    # before the readiness poll — not after it — or a poll that times out leaks a live charge.
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=version, ProvisionedConcurrentExecutions=1
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(
            FunctionName=fn, Qualifier=version
        )
    )
    status = _poll(
        lambda: (
            lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=version)
        ).get("Status") == "READY",
        timeout_s=420,
        interval_s=5.0,
    )
    pc = lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=version)
    assert status and pc["Status"] == "READY", (
        f"provisioned concurrency never became READY within 420s: {pc!r}"
    )
    assert pc["AvailableProvisionedConcurrentExecutions"] == 1, (
        f"READY was reported but no capacity is available: {pc!r}"
    )

    # ---- the provisioned leg: served by an environment initialised out of band ----
    pc_report, pc_tail = _invoke_tail(lam, qualified)
    assert "REPORT RequestId" in pc_report, f"no REPORT line in the tail log: {pc_report!r}"
    assert "Init Duration" not in pc_report, (
        f"a provisioned-concurrency invocation charged an init to the invocation itself: "
        f"{pc_report!r}. With a READY provisioned environment the init has already happened, so "
        f"the REPORT line must carry no Init Duration"
    )
    # …and the init did happen, just not inside this invocation: it has its own INIT_REPORT line.
    init_reports = [ln for ln in pc_tail.splitlines() if ln.startswith("INIT_REPORT")]
    assert init_reports, (
        f"the provisioned environment reported no INIT_REPORT line either, so nothing shows the "
        f"module scope was ever initialised: {pc_tail!r}"
    )
    assert "Init Duration" in init_reports[0], (
        f"the INIT_REPORT line carries no Init Duration: {init_reports[0]!r}"
    )

    # The unprovisioned $LATEST is untouched by the version's provisioning: a second $LATEST
    # invocation is now WARM, so it reports no init either — which pins that the absence above is
    # about environment reuse and not about this runtime never reporting inits.
    warm_report, _ = _invoke_tail(lam, fn)
    assert "Init Duration" not in warm_report, (
        f"a warm reuse of the already-initialised $LATEST environment re-reported an init: "
        f"{warm_report!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
