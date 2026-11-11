"""stream-provisioned-environment-reports-provisioned-initialization-type."""

from __future__ import annotations

import base64
import concurrent.futures
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-provisioned-environment-reports-provisioned-initialization-type"
GROUP = 'concurrency'
SERVICES = ['lambda']

PROVISIONED = 1     # what this check asks for; read back off the API before it is asserted on
BURST = 6           # deliberately wider than PROVISIONED, so most of it must spill over
HOLD_S = 6          # long enough that the whole burst is in flight together

# AWS_LAMBDA_INITIALIZATION_TYPE is set by the execution environment, so the handler reports it.
HANDLER = """\
import json
import os
import time
import uuid

ENV_ID = str(uuid.uuid4())
INIT_EPOCH = time.time()
INVOKES = 0


def handler(event, context):
    global INVOKES
    INVOKES += 1
    start = time.time()
    time.sleep(float(event.get("hold_s", 0)))
    out = {
        "env_id": ENV_ID,
        "init_type": os.environ.get("AWS_LAMBDA_INITIALIZATION_TYPE"),
        "invokes": INVOKES,
        "version": context.function_version,
        "init_epoch": INIT_EPOCH,
        "start": start,
        "end": time.time(),
    }
    print("HANDLER " + json.dumps(out, sort_keys=True))
    return out
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Handlers in provisioned environments read AWS_LAMBDA_INITIALIZATION_TYPE
    'provisioned-concurrency'; $LATEST and burst spillover beyond the provisioned count read
    'on-demand', and no more environments than were provisioned report the provisioned type.
    """
    lam = ctx.client("lambda")

    settings = lam.get_account_settings()["AccountLimit"]
    assert settings["UnreservedConcurrentExecutions"] >= BURST + PROVISIONED, (
        f"this account has only {settings['UnreservedConcurrentExecutions']!r} unreserved "
        f"concurrent executions left, which cannot serve a {BURST}-wide burst plus "
        f"{PROVISIONED} provisioned — that is account state, not a fidelity result: {settings!r}"
    )

    role_arn = _execution_role(ctx)
    fn = ctx.unique_name("sim2real-behav-pcinit-")
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": HANDLER})},
        MemorySize=512,
        Timeout=60,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(lam, fn)

    version = lam.publish_version(FunctionName=fn)["Version"]
    _wait_active(lam, f"{fn}:{version}")

    # Provisioned concurrency BILLS FROM THE MOMENT IT IS READY, so the delete is registered before
    # the readiness poll — not after it — or a poll that times out leaks a live charge.
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=version, ProvisionedConcurrentExecutions=PROVISIONED
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=version)
    )

    # Invoked while the version's capacity is still allocating: a genuinely cold $LATEST baseline.
    cold = _invoke(lam, fn, hold_s=0)
    assert cold["init_type"] == "on-demand", (
        f"the first-ever invocation of $LATEST was not pre-warmed by anything, so the handler must "
        f"read AWS_LAMBDA_INITIALIZATION_TYPE='on-demand', got {cold['init_type']!r} in {cold!r}"
    )
    assert cold["invokes"] == 1, (
        f"a freshly initialised environment must report its first invocation, got "
        f"invokes={cold['invokes']!r} in {cold!r}"
    )
    assert cold["version"] == "$LATEST", (
        f"an unqualified invoke must run $LATEST, but the handler reported "
        f"version={cold['version']!r}"
    )

    pc = _wait_provisioned_ready(lam, fn, version, _budget(ctx, 600.0))
    requested = pc["RequestedProvisionedConcurrentExecutions"]
    assert requested == PROVISIONED, (
        f"GetProvisionedConcurrencyConfig echoed Requested={requested!r} for a config created with "
        f"{PROVISIONED}: {pc!r}"
    )
    assert pc["AvailableProvisionedConcurrentExecutions"] == requested, (
        f"Status=READY was reported but only "
        f"{pc['AvailableProvisionedConcurrentExecutions']!r} of {requested!r} provisioned "
        f"executions are available: {pc!r}"
    )

    # ---- the effect: an invocation of the provisioned version runs in a pre-warmed environment ----
    warm = _invoke(lam, fn, hold_s=0, qualifier=version)
    assert warm["init_type"] == "provisioned-concurrency", (
        f"an invocation served by a READY provisioned environment must see "
        f"AWS_LAMBDA_INITIALIZATION_TYPE='provisioned-concurrency' from inside the handler, got "
        f"{warm['init_type']!r} in {warm!r} — the environment was not pre-warmed, whatever the "
        f"control plane reported"
    )
    assert warm["version"] == version, (
        f"the qualified invoke must run version {version!r}, handler reported {warm['version']!r}"
    )
    assert warm["env_id"] != cold["env_id"], (
        f"the provisioned version and $LATEST must be distinct environments, both reported "
        f"env_id {warm['env_id']!r}"
    )
    assert warm["init_epoch"] < warm["start"], (
        f"the provisioned environment's module scope must have run BEFORE the invocation that used "
        f"it: init_epoch {warm['init_epoch']!r} is not earlier than start {warm['start']!r}"
    )

    # ...and it is the SAME pre-warmed environment on the next invocation.
    warm2 = _invoke(lam, fn, hold_s=0, qualifier=version)
    assert warm2["env_id"] == warm["env_id"], (
        f"a second sequential invocation must reuse the one provisioned environment, got "
        f"{warm2['env_id']!r} after {warm['env_id']!r}"
    )
    assert warm2["invokes"] == warm["invokes"] + 1, (
        f"the reused environment must carry its module state forward: invokes went "
        f"{warm['invokes']!r} -> {warm2['invokes']!r}"
    )
    assert warm2["init_type"] == "provisioned-concurrency", (
        f"the reused provisioned environment must still report 'provisioned-concurrency', got "
        f"{warm2['init_type']!r}"
    )

    # ---- absence leg: the same code, one qualifier away, is not provisioned ----
    unprovisioned = _invoke(lam, fn, hold_s=0)
    assert unprovisioned["init_type"] == "on-demand", (
        f"$LATEST carries no provisioned concurrency config, so its handler must still read "
        f"'on-demand'; got {unprovisioned['init_type']!r} in {unprovisioned!r} — provisioning "
        f"leaked to a qualifier that was never provisioned"
    )
    assert unprovisioned["env_id"] != warm["env_id"], (
        f"the provisioned environment belongs to version {version!r} alone, but a $LATEST "
        f"invocation was served by it: both reported env_id {warm['env_id']!r}"
    )
    assert unprovisioned["version"] == "$LATEST", (
        f"an unqualified invoke must run $LATEST, handler reported "
        f"{unprovisioned['version']!r}"
    )

    # ---- absence leg: capacity is bounded by its number, so a wider burst spills over ----
    burst = _burst(lam, fn, version, BURST, HOLD_S)
    assert len(burst) == BURST, f"expected {BURST} responses from the burst, got {len(burst)}"
    # An environment serves one request at a time, so BURST requests held in flight together are
    # served by BURST environments; a target that queues them reuses fewer.
    burst_envs = {b["env_id"] for b in burst}
    assert len(burst_envs) == BURST, (
        f"{BURST} simultaneous invocations were served by {len(burst_envs)} execution "
        f"environment(s), so they were queued and nothing below is a statement about concurrency"
    )
    kinds = sorted({b["init_type"] for b in burst})
    assert kinds == ["on-demand", "provisioned-concurrency"], (
        f"a {BURST}-wide burst against {requested} provisioned execution(s) must be served by both "
        f"kinds of environment, got {kinds!r} across {[b['init_type'] for b in burst]!r}"
    )
    provisioned_envs = {b["env_id"] for b in burst if b["init_type"] == "provisioned-concurrency"}
    assert len(provisioned_envs) <= requested, (
        f"{len(provisioned_envs)} distinct environments reported 'provisioned-concurrency' while "
        f"only {requested} was provisioned: {sorted(provisioned_envs)!r}"
    )
    assert provisioned_envs <= {warm["env_id"]}, (
        f"the provisioned environment must be the one already observed ({warm['env_id']!r}), got "
        f"{sorted(provisioned_envs)!r}"
    )
    spillover = [b for b in burst if b["init_type"] == "on-demand"]
    assert len(spillover) >= BURST - requested, (
        f"with {requested} provisioned execution(s) and {BURST} simultaneous invocations, at least "
        f"{BURST - requested} must run in environments that were NOT pre-warmed; only "
        f"{len(spillover)} reported 'on-demand': {[b['init_type'] for b in burst]!r}"
    )
    assert all(b["invokes"] == 1 for b in spillover), (
        f"every spilled-over invocation must land in a freshly initialised environment, got "
        f"invokes {[b['invokes'] for b in spillover]!r}"
    )
    assert len({b["env_id"] for b in spillover}) == len(spillover), (
        f"the {len(spillover)} simultaneous spilled-over invocations cannot share an environment: "
        f"{[b['env_id'] for b in spillover]!r}"
    )


def _budget(ctx, cap_s: float, reserve_s: float = 60.0) -> float:
    """A wait's cap, cut to the check's remaining time so it fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _invoke(lam, fn: str, *, hold_s: float, qualifier: str | None = None) -> dict:
    """Invoke once; the returned payload must equal the JSON the handler printed to its log."""
    kwargs = {
        "FunctionName": fn,
        "InvocationType": "RequestResponse",
        "LogType": "Tail",
        "Payload": json.dumps({"hold_s": hold_s}).encode(),
    }
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke(**kwargs)
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r}, body {raw!r}"
    assert resp.get("FunctionError") is None, (
        f"{fn}: FunctionError {resp.get('FunctionError')!r}, body {raw!r}"
    )
    body = json.loads(raw)

    tail = base64.b64decode(resp["LogResult"]).decode()
    printed = [
        json.loads(line.split("HANDLER ", 1)[1])
        for line in tail.splitlines()
        if "HANDLER " in line
    ]
    assert len(printed) == 1, (
        f"{fn}: the handler must have printed exactly one HANDLER record for this invocation, got "
        f"{len(printed)} in {tail!r}"
    )
    assert printed[0] == body, (
        f"{fn}: the returned payload and the handler's own stdout disagree: returned {body!r}, "
        f"printed {printed[0]!r}"
    )
    return body


def _burst(lam, fn: str, qualifier: str, n: int, hold_s: float) -> list[dict]:
    """n simultaneous invokes of one qualifier, without log read-back."""
    def _one(_i):
        resp = lam.invoke(
            FunctionName=fn, Qualifier=qualifier, InvocationType="RequestResponse",
            Payload=json.dumps({"hold_s": hold_s}).encode(),
        )
        raw = resp["Payload"].read()
        assert resp.get("FunctionError") is None, (
            f"{fn}:{qualifier} FunctionError {resp.get('FunctionError')!r}: {raw!r}"
        )
        assert raw, f"{fn}:{qualifier} returned an empty payload: {resp!r}"
        return json.loads(raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(_one, range(n)))


def _wait_provisioned_ready(lam, fn: str, qualifier: str, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=qualifier)
        if last["Status"] == "FAILED":
            raise AssertionError(
                f"provisioned concurrency for {fn}:{qualifier} went to FAILED: "
                f"{last.get('StatusReason')!r}"
            )
        if last["Status"] == "READY":
            return last
        time.sleep(5)
    raise AssertionError(
        f"provisioned concurrency for {fn}:{qualifier} never became READY within {timeout_s}s; "
        f"last={last!r}"
    )


def _execution_role(ctx) -> str:
    """Create a Lambda execution role with basic execution permissions."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-pcinit-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # IAM propagation is absorbed at first use by the deadline-bound retry in _create_function.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the role-propagation refusal. Raises on deadline."""
    name = kwargs["FunctionName"]
    # Registered before the delete so LIFO reaps the log group after delete_function, which
    # does not remove /aws/lambda/<fn>.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last!r}")


def _reap_log_group(ctx, name: str, rounds: int = 6, interval_s: float = 8.0) -> None:
    """Delete /aws/lambda/<name> until two consecutive polls find it absent; raise otherwise.

    A log stream buffered by an already-returned invocation can recreate the group after a delete.
    """
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent_streak = 0
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
        found = [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if g["logGroupName"] == group
        ]
        absent_streak = 0 if found else absent_streak + 1
        if absent_streak >= 2:
            return
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _wait_active(lam, name: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {last.get('StateReasonCode')!r} "
                f"{last.get('StateReason')!r}"
            )
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(2)
    raise AssertionError(f"{name} never reached State=Active within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
