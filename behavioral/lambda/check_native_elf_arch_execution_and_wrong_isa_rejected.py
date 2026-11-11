"""native-elf-arch-execution-and-wrong-isa-rejected."""

from __future__ import annotations

import base64
import io
import json
import re
import struct
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "native-elf-arch-execution-and-wrong-isa-rejected"
GROUP = 'rejection'
SERVICES = ['lambda']

TIMEOUT_S = 17

EM_X86_64 = 0x3E
EM_AARCH64 = 0xB7

# The runtime is a shell poll loop that shells out to /var/task/archprobe — a NATIVE static ELF
# with no interpreter and no libc — and reports its stdout, its exit status, and uname -m, plus a
# per-process boot id: Lambda may recycle an environment at any time, so counters are per boot.
BOOTSTRAP = r'''#!/bin/sh
set -u
API="$AWS_LAMBDA_RUNTIME_API"
BOOT=$(cat /proc/sys/kernel/random/uuid)
N=0
while true; do
  N=$((N+1))
  curl -sS -LD /tmp/hdr -o /tmp/evt "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Aws-Request-Id:/ {print $2}' /tmp/hdr | tr -d '\r')
  OUT=$(/var/task/archprobe 2>/dev/null); RC=$?
  OUT=$(printf '%s' "$OUT" | tr -d '\n\\"')
  printf '{"invocation":%s,"boot":"%s","request_id":"%s","probe_out":"%s","probe_rc":%s,"uname_machine":"%s","pid":%s,"event":%s}' \
    "$N" "$BOOT" "$RID" "$OUT" "$RC" "$(uname -m)" "$$" "$(cat /tmp/evt)" > /tmp/resp.json
  curl -sS -X POST "http://$API/2018-06-01/runtime/invocation/$RID/response" -d @/tmp/resp.json >/dev/null
done
'''

_ELF_BASE = 0x400000
_EHDR = 64
_PHDR = 56
_CODE_OFF = _EHDR + _PHDR


def _static_elf(machine, code, msg):
    """A minimal ET_EXEC ELF64: one PT_LOAD segment, no interpreter, no libc.

    A native instruction stream for exactly one architecture, unlike arch-neutral bytecode.
    """
    total = _CODE_OFF + len(code) + len(msg)
    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack(
        "<HHIQQQIHHHHHH", 2, machine, 1, _ELF_BASE + _CODE_OFF, _EHDR, 0, 0,
        _EHDR, _PHDR, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, _ELF_BASE, _ELF_BASE, total, total, 0x1000)
    assert len(ehdr) == _EHDR and len(phdr) == _PHDR, "ELF header sizes are fixed by the spec"
    return ehdr + phdr + code + msg


def _elf_x86_64(msg):
    """write(1, msg, len); exit(0) in x86-64 machine code."""
    code_len = 36
    code = (
        b"\xb8\x01\x00\x00\x00"                                        # mov  eax, 1  (SYS_write)
        b"\xbf\x01\x00\x00\x00"                                        # mov  edi, 1  (stdout)
        + b"\x48\xbe" + struct.pack("<Q", _ELF_BASE + _CODE_OFF + code_len)   # mov rsi, msg
        + b"\xba" + struct.pack("<I", len(msg))                        # mov  edx, len
        + b"\x0f\x05"                                                  # syscall
        b"\xb8\x3c\x00\x00\x00"                                        # mov  eax, 60 (SYS_exit)
        b"\x31\xff"                                                    # xor  edi, edi
        b"\x0f\x05"                                                    # syscall
    )
    assert len(code) == code_len, f"x86-64 code is {len(code)} bytes, not {code_len}"
    return _static_elf(EM_X86_64, code, msg)


def _elf_aarch64(msg):
    """write(1, msg, len); exit(0) in AArch64 machine code."""
    code_len = 32
    offset = (_CODE_OFF + code_len) - (_CODE_OFF + 4)     # msg, relative to the ADR instruction
    adr = ((offset & 3) << 29) | (0b10000 << 24) | (((offset >> 2) & 0x7FFFF) << 5) | 1
    words = [
        0xD2800000 | (1 << 5) | 0,               # movz x0, #1   (stdout)
        adr,                                     # adr  x1, msg
        0xD2800000 | (len(msg) << 5) | 2,        # movz x2, #len
        0xD2800000 | (64 << 5) | 8,              # movz x8, #64  (SYS_write)
        0xD4000001,                              # svc  #0
        0xD2800000 | (93 << 5) | 8,              # movz x8, #93  (SYS_exit)
        0xD2800000 | (0 << 5) | 0,               # movz x0, #0
        0xD4000001,                              # svc  #0
    ]
    code = b"".join(struct.pack("<I", w) for w in words)
    assert len(code) == code_len, f"aarch64 code is {len(code)} bytes, not {code_len}"
    return _static_elf(EM_AARCH64, code, msg)


def _e_machine(blob):
    """The e_machine field of an ELF64 image: offset 18, little-endian u16."""
    assert blob[:4] == b"\x7fELF", f"not an ELF image: {blob[:8]!r}"
    return struct.unpack_from("<H", blob, 18)[0]


def _make_zip(entries):
    """Build a deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
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
        # /aws/lambda/<fn> is created by the service on FIRST INVOKE and outlives the function.
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _deploy(ctx, lam, label, zipbytes, arch):
    name = ctx.unique_name(f"sim2real-behav-{label}-")
    _create_function(lam,
        FunctionName=name, Runtime="provided.al2023", Handler="bootstrap",
        Role=_role_arn(ctx), Code={"ZipFile": zipbytes},
        Architectures=[arch], MemorySize=512, Timeout=TIMEOUT_S,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{name} entered State=Failed: {cfg.get('StateReason')!r}")
        if cfg["State"] == "Active":
            return name, cfg
        time.sleep(1)
    raise AssertionError(f"{name} did not reach State=Active within 180s")


def _invoke(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode(), LogType="Tail")
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": resp["Payload"].read(),
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
    }


def _body(fn, r):
    assert r["status"] == 200, f"{fn}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] is None, (
        f"{fn}: FunctionError={r['function_error']!r}, payload {r['raw']!r}"
    )
    return json.loads(r["raw"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Architectures selects the native ISA that executes: hand-built static ELFs print their own arch,
    an x86-64 ELF fails to exec (126) in an arm64 sandbox, and one zip yields ExitError on x86_64
    but InvalidEntrypoint on arm64.
    """
    lam = ctx.client("lambda")
    probe_x86 = _elf_x86_64(b"x86_64\n")
    probe_arm = _elf_aarch64(b"aarch64\n")

    # (1) prove the check's own inputs are two different instruction sets before anything is uploaded
    assert _e_machine(probe_x86) == EM_X86_64, (
        f"the locally built x86 probe declares e_machine {_e_machine(probe_x86):#x}, not "
        f"{EM_X86_64:#x} (EM_X86_64)"
    )
    assert _e_machine(probe_arm) == EM_AARCH64, (
        f"the locally built arm probe declares e_machine {_e_machine(probe_arm):#x}, not "
        f"{EM_AARCH64:#x} (EM_AARCH64)"
    )
    assert probe_x86 != probe_arm, "the two probes are the same bytes; there is nothing to compare"

    sh = ("bootstrap", BOOTSTRAP, 0o100755)
    zip_x86 = _make_zip([sh, ("archprobe", probe_x86, 0o100755)])
    zip_arm = _make_zip([sh, ("archprobe", probe_arm, 0o100755)])
    # ONE zip, deployed twice under two different Architectures. Byte-identical by construction.
    zip_boot = _make_zip([("bootstrap", probe_x86, 0o100755)])

    fn_x86, cfg_x86 = _deploy(ctx, lam, "elfx86", zip_x86, "x86_64")
    fn_arm, cfg_arm = _deploy(ctx, lam, "elfarm", zip_arm, "arm64")
    fn_cross, _ = _deploy(ctx, lam, "elfcross", zip_x86, "arm64")
    fn_boot_x86, _ = _deploy(ctx, lam, "elfbootx", zip_boot, "x86_64")
    fn_boot_arm, _ = _deploy(ctx, lam, "elfboota", zip_boot, "arm64")

    # ---- arms 1 and 2: each matched leg executes its own instruction stream -------------------
    x86_bodies = [_body(fn_x86, _invoke(lam, fn_x86, {"i": i})) for i in (1, 2)]
    arm_bodies = [_body(fn_arm, _invoke(lam, fn_arm, {"i": i})) for i in (1, 2)]

    assert x86_bodies[0]["probe_out"] == "x86_64", (
        f"the x86_64 function's native probe printed {x86_bodies[0]['probe_out']!r} with exit "
        f"status {x86_bodies[0]['probe_rc']!r}; an EM_X86_64 instruction stream did not run"
    )
    assert arm_bodies[0]["probe_out"] == "aarch64", (
        f"the arm64 function's native probe printed {arm_bodies[0]['probe_out']!r} with exit "
        f"status {arm_bodies[0]['probe_rc']!r}; an EM_AARCH64 instruction stream did not run"
    )
    assert arm_bodies[0]["probe_out"] != x86_bodies[0]["probe_out"], (
        f"both legs' native probes printed {x86_bodies[0]['probe_out']!r} — Architectures is being "
        f"stored but not honoured, so both ran on the host's architecture"
    )
    for label, bodies, want in (("x86_64", x86_bodies, "x86_64"), ("arm64", arm_bodies, "aarch64")):
        assert bodies[0]["probe_rc"] == 0, (
            f"the {label} function's native probe exited {bodies[0]['probe_rc']!r}, not 0"
        )
        # the kernel agrees with the binary, so a substituted shim that only prints is caught
        assert bodies[0]["uname_machine"] == want, (
            f"the {label} function's sandbox reports uname -m == {bodies[0]['uname_machine']!r}, "
            f"which must agree with what the native binary printed ({want!r})"
        )
        # the poll loop survives across invokes on both architectures: per runtime process
        # (boot id) the counter climbs 1..n under one pid
        per_boot: dict = {}
        for b in bodies:
            per_boot.setdefault(b["boot"], []).append(b)
        for boot, served in per_boot.items():
            assert [b["invocation"] for b in served] == list(range(1, len(served) + 1)), (
                f"the {label} function's runtime process {boot} reported invocation counters "
                f"{[b['invocation'] for b in served]!r}, expected 1..{len(served)}"
            )
            assert len({b["pid"] for b in served}) == 1, (
                f"the {label} function's runtime process {boot} reported pids "
                f"{sorted({b['pid'] for b in served})!r}; one poll loop means one process"
            )
        assert len({b["request_id"] for b in bodies}) == 2, (
            f"the {label} function served two invokes under one request id "
            f"{bodies[0]['request_id']!r}"
        )
    assert arm_bodies[0]["event"] == {"i": 1}, (
        f"the arm64 runtime received event {arm_bodies[0]['event']!r}, not the payload sent"
    )

    # configuration and execution are the same fact
    assert cfg_x86["Architectures"] == ["x86_64"], f"{cfg_x86.get('Architectures')!r}"
    assert cfg_arm["Architectures"] == ["arm64"], f"{cfg_arm.get('Architectures')!r}"
    assert cfg_x86["CodeSize"] != cfg_arm["CodeSize"], (
        f"both functions report CodeSize {cfg_x86['CodeSize']!r} — the two legs are the same "
        f"artifact uploaded twice, so nothing about the architecture was under test"
    )

    # ---- arm 3 (negative, in-band): a cross-ISA binary inside a WORKING arm64 sandbox ---------
    cross = _body(fn_cross, _invoke(lam, fn_cross, {"i": 1}))
    assert cross["probe_rc"] == 126, (
        f"an x86-64 ELF invoked inside an arm64 sandbox exited {cross['probe_rc']!r}, expected 126 "
        f"(exec format error) — the arm64 execution environment executed an x86-64 instruction "
        f"stream, which a real arm64 kernel cannot do"
    )
    # effect-absent: the binary produced no output at all, i.e. it never ran
    assert cross["probe_out"] == "", (
        f"the cross-ISA probe still printed {cross['probe_out']!r}; a binary that failed to exec "
        f"cannot have written anything"
    )
    # positive control in the same sandbox: everything EXCEPT the ISA works
    assert cross["uname_machine"] == "aarch64", (
        f"the cross-ISA function's sandbox reports uname -m == {cross['uname_machine']!r}; the one "
        f"broken thing must be the binary's architecture, not the sandbox"
    )
    assert cross["invocation"] == 1 and cross["request_id"], (
        f"the cross-ISA function's own shell runtime did not complete a Runtime API round trip: "
        f"{cross!r}"
    )

    # ---- arm 4: ONE zip, two Architectures, two DIFFERENT Lambda error classes ----------------
    ran = _invoke(lam, fn_boot_x86, {"i": 1})
    assert ran["function_error"] == "Unhandled", (
        f"a bootstrap that exits without answering the Runtime API reported FunctionError="
        f"{ran['function_error']!r}, expected 'Unhandled': {ran['raw']!r}"
    )
    ran_body = json.loads(ran["raw"])
    assert ran_body["errorType"] == "Runtime.ExitError", (
        f"on x86_64 the native bootstrap produced errorType {ran_body['errorType']!r}, expected "
        f"'Runtime.ExitError' — it DID exec and then exited, which is a process-supervision "
        f"outcome, not an entrypoint one"
    )
    # it really executed: its stdout is in the function's own log
    assert "x86_64" in ran["log"], (
        f"the x86_64 leg's log tail does not contain the string the native bootstrap prints; it "
        f"never ran. log was {ran['log']!r}"
    )

    refused = _invoke(lam, fn_boot_arm, {"i": 1})
    assert refused["function_error"] == "Unhandled", (
        f"the same bytes on arm64 reported FunctionError={refused['function_error']!r}: "
        f"{refused['raw']!r}"
    )
    refused_body = json.loads(refused["raw"])
    assert refused_body["errorType"] == "Runtime.InvalidEntrypoint", (
        f"on arm64 the x86-64 bootstrap produced errorType {refused_body['errorType']!r}, expected "
        f"'Runtime.InvalidEntrypoint' — the arm64 sandbox must fail to EXEC it"
    )
    assert refused_body["errorMessage"] == "failed to exec /var/task/bootstrap", (
        f"the message was {refused_body['errorMessage']!r}, expected "
        f"'failed to exec /var/task/bootstrap'"
    )
    assert refused_body["errorType"] != ran_body["errorType"], (
        f"one byte-identical zip produced errorType {ran_body['errorType']!r} under both "
        f"Architectures — the architecture had no effect on whether the binary could be exec'd, "
        f"which is what running everything on the host arch looks like"
    )
    # effect-absent: nothing of ours ran on the arm64 leg, so its stdout is nowhere in the log
    assert "x86_64" not in refused["log"], (
        f"the arm64 leg's log contains the x86-64 binary's own stdout, so it executed after all: "
        f"{refused['log']!r}"
    )
    assert not re.search(r"^REPORT RequestId: .*\tInit Duration:", refused["log"], re.M), (
        f"the arm64 leg's REPORT line records a successful Init Duration, but init failed to exec "
        f"the entrypoint: {refused['log']!r}"
    )
    # and an unusable artifact is not eagerly rejected at create time nor parked in Failed
    for name in (fn_boot_x86, fn_boot_arm, fn_cross):
        state = lam.get_function_configuration(FunctionName=name)["State"]
        assert state == "Active", (
            f"{name} is in State={state!r}, expected 'Active' — an artifact that cannot run is "
            f"still a validly created function"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
