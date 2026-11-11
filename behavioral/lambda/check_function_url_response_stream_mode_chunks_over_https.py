"""function-url-response-stream-mode-chunks-over-https."""

from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-url-response-stream-mode-chunks-over-https"
GROUP = "function_url"
SERVICES = ["lambda"]

# A check detail containing this marker grades as an unimplemented endpoint data plane (a real
# fidelity fail), not as a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_STATEMENT_ID = "sim2real-behav-url-iam"
_CHUNKS = 4
_GAP_MS = 700

_HANDLER_JS = f"""
const {{ setTimeout: sleep }} = require('timers/promises');

exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {{
  for (let i = 0; i < {_CHUNKS}; i++) {{
    responseStream.write(`chunk-${{i}}\\n`);
    if (i < {_CHUNKS - 1}) {{
      await sleep({_GAP_MS});
    }}
  }}
  responseStream.end();
}});
"""

_EXPECTED_LINES = [f"chunk-{i}" for i in range(_CHUNKS)]
# The handler's own accumulated sleep before it finishes, in seconds. Nothing about the target.
_HANDLER_RUNTIME_S = (_CHUNKS - 1) * _GAP_MS / 1000.0


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """In RESPONSE_STREAM mode a function URL answers chunked and delivers bytes while the handler
    runs; switching the same URL to BUFFERED withholds every byte until it finishes, and switching
    back restores streaming.
    """
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_execution_role(ctx, iam)

    fn = ctx.unique_name("sim2real-behav-urlstream-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="nodejs22.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": _HANDLER_JS})},
        MemorySize=256,
        Timeout=60,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    created = lam.create_function_url_config(
        FunctionName=fn, AuthType="AWS_IAM", InvokeMode="RESPONSE_STREAM"
    )
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=fn))
    url = created["FunctionUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p
    assert created["InvokeMode"] == "RESPONSE_STREAM", (
        f"CreateFunctionUrlConfig must store InvokeMode=RESPONSE_STREAM, echoed "
        f"{created['InvokeMode']!r}"
    )

    lam.add_permission(
        FunctionName=fn,
        StatementId=_STATEMENT_ID,
        Action="lambda:InvokeFunctionUrl",
        Principal=account,
        FunctionUrlAuthType="AWS_IAM",
    )

    # ---- leg 1: streaming. Retry only for URL/permission propagation, with a deadline. ----
    streamed = _poll_until(
        lambda: _signed_get_lines(ctx, url),
        lambda obs: obs["status"] == 200,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"the AWS_IAM function URL {url} answering 200 to a SigV4-signed GET",
    )
    # The first 200 may include a cold start; time a second, warm GET.
    streamed = _signed_get_lines(ctx, url)
    assert streamed["status"] == 200, f"the warm GET to {url} answered {streamed['status']}"
    assert streamed["lines"] == _EXPECTED_LINES, (
        f"the streamed body must reassemble to the handler's chunks in order: expected "
        f"{_EXPECTED_LINES}, got {streamed['lines']}"
    )
    assert streamed["content_length"] is None, (
        f"a RESPONSE_STREAM URL cannot know the body length up front, yet it answered with "
        f"Content-Length: {streamed['content_length']!r}"
    )
    assert (streamed["transfer_encoding"] or "").lower() == "chunked", (
        f"a RESPONSE_STREAM URL must answer with Transfer-Encoding: chunked, got "
        f"{streamed['transfer_encoding']!r} (headers: {streamed['headers']})"
    )
    assert streamed["ttfb_s"] < _HANDLER_RUNTIME_S, (
        f"the first chunk must arrive BEFORE the handler finishes its "
        f"{_HANDLER_RUNTIME_S:.1f}s of work; it took {streamed['ttfb_s']:.3f}s, so the response was "
        f"buffered"
    )
    assert streamed["max_gap_s"] >= _GAP_MS / 2000.0, (
        f"no inter-chunk gap of at least {_GAP_MS / 2000.0:.2f}s was observed "
        f"(max {streamed['max_gap_s']:.3f}s) although the handler sleeps {_GAP_MS}ms between "
        f"writes: arrivals {streamed['arrivals']}"
    )

    # ---- leg 2: break exactly one thing — the invoke mode on the SAME URL ----
    lam.update_function_url_config(FunctionName=fn, InvokeMode="BUFFERED")
    stored = lam.get_function_url_config(FunctionName=fn)["InvokeMode"]
    assert stored == "BUFFERED", (
        f"UpdateFunctionUrlConfig must store InvokeMode=BUFFERED, GetFunctionUrlConfig reports "
        f"{stored!r}"
    )
    buffered = _poll_until(
        lambda: _signed_get_lines(ctx, url),
        lambda obs: obs["status"] == 200 and obs["content_length"] is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the URL {url} switching to a buffered response (a Content-Length header) after "
            "InvokeMode=BUFFERED"
        ),
    )
    assert buffered["lines"] == _EXPECTED_LINES, (
        f"BUFFERED mode must still deliver the whole body: expected {_EXPECTED_LINES}, got "
        f"{buffered['lines']}"
    )
    assert (buffered["transfer_encoding"] or "").lower() != "chunked", (
        f"a BUFFERED URL must not answer with chunked transfer encoding; headers were "
        f"{buffered['headers']}"
    )
    assert buffered["ttfb_s"] >= _HANDLER_RUNTIME_S, (
        f"in BUFFERED mode no byte may leave before the handler finishes its "
        f"{_HANDLER_RUNTIME_S:.1f}s of work, but the first byte arrived after only "
        f"{buffered['ttfb_s']:.3f}s"
    )
    assert buffered["ttfb_s"] > streamed["ttfb_s"], (
        f"BUFFERED time-to-first-byte ({buffered['ttfb_s']:.3f}s) must exceed RESPONSE_STREAM's "
        f"({streamed['ttfb_s']:.3f}s) on the same URL and handler; the two modes are "
        f"indistinguishable on this target"
    )

    # ---- leg 3: restore — streaming resumes, so leg 2 measured the mode, not a slow moment ----
    lam.update_function_url_config(FunctionName=fn, InvokeMode="RESPONSE_STREAM")
    restored = _poll_until(
        lambda: _signed_get_lines(ctx, url),
        lambda obs: obs["status"] == 200 and obs["content_length"] is None,
        timeout_s=120.0,
        interval_s=5.0,
        description=(
            f"the URL {url} returning to a streamed response after InvokeMode=RESPONSE_STREAM"
        ),
    )
    assert restored["lines"] == _EXPECTED_LINES, (
        f"after restoring RESPONSE_STREAM the body must still be complete: expected "
        f"{_EXPECTED_LINES}, got {restored['lines']}"
    )
    assert restored["ttfb_s"] < _HANDLER_RUNTIME_S, (
        f"after restoring RESPONSE_STREAM the first chunk must again arrive before the handler "
        f"finishes ({_HANDLER_RUNTIME_S:.1f}s); it took {restored['ttfb_s']:.3f}s"
    )


# ===== helpers =====

def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _signed_get_lines(ctx, url: str, timeout_s: float = 60.0) -> dict:
    """SigV4-sign a GET to a function URL and read the body line by line, timing each arrival.

    Signs with ctx's credentials, not boto3's ambient chain, so the request has the right principal.
    """
    signer_creds = ctx.client("lambda")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign the function URL request")
    frozen = signer_creds.get_frozen_credentials()

    aws_req = AWSRequest(method="GET", url=url, data=None, headers={})
    SigV4Auth(frozen, "lambda", ctx.region).add_auth(aws_req)
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, data=None, method="GET", headers={**(dict(aws_req.headers)), **_route})

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            arrivals: list[float] = []
            lines: list[str] = []
            while True:
                raw = resp.readline()
                if not raw:
                    break
                arrivals.append(time.monotonic() - t0)
                lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read()[:300].decode("utf-8", errors="replace")
        return {
            "status": exc.code,
            "lines": [],
            "arrivals": [],
            "ttfb_s": None,
            "max_gap_s": None,
            "headers": {k.lower(): v for k, v in exc.headers.items()},
            "content_length": exc.headers.get("Content-Length"),
            "transfer_encoding": exc.headers.get("Transfer-Encoding"),
            "body": body,
        }
    except urllib.error.URLError as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the function URL {url} did not answer a signed GET at all: "
            f"{exc.reason}"
        ) from exc

    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    return {
        "status": status,
        "lines": lines,
        "arrivals": [round(a, 3) for a in arrivals],
        "ttfb_s": arrivals[0] if arrivals else None,
        "max_gap_s": max(gaps) if gaps else 0.0,
        "headers": headers,
        "content_length": headers.get("content-length"),
        "transfer_encoding": headers.get("transfer-encoding"),
        "body": "\n".join(lines),
    }


def _create_execution_role(ctx, iam) -> str:
    """Create this check's own execution role in-check, tagged so a leftover can be found by tag."""
    role_name = ctx.unique_name("sim2real-behav-urlstream-role-")
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
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
