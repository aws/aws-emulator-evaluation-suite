"""ruby-reserved-env-vars-override-attempt."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = 'ruby-reserved-env-vars-override-attempt'
GROUP = 'execution_environment'
SERVICES = ['lambda']

_RUNTIME = "ruby3.4"
_API_VERSION = "3.4.0"
_GEM_NAME = "sim2real_env_gem"
_GEM_VERSION = "1.0.0"

_GEM_LIB = (
    'module Sim2realEnvGem\n'
    '  def self.greet\n'
    '    "env-gem-ok"\n'
    '  end\n'
    'end\n'
)

_GEMSPEC = (
    '# -*- encoding: utf-8 -*-\n'
    f'# stub: {_GEM_NAME} {_GEM_VERSION} ruby lib\n\n'
    'Gem::Specification.new do |s|\n'
    f'  s.name = "{_GEM_NAME}".freeze\n'
    f'  s.version = "{_GEM_VERSION}".freeze\n'
    '  s.require_paths = ["lib".freeze]\n'
    '  s.authors = ["sim2real".freeze]\n'
    '  s.summary = "env override test gem".freeze\n'
    f'  s.files = ["lib/{_GEM_NAME}.rb".freeze]\n'
    'end\n'
)

_HANDLER = (
    'def handler(event:, context:)\n'
    '  loaded = begin\n'
    f'    require "{_GEM_NAME}"\n'
    '    Sim2realEnvGem.greet\n'
    '  rescue LoadError => e\n'
    '    e.message\n'
    '  end\n'
    '  {"aws_execution_env" => ENV["AWS_EXECUTION_ENV"], "gem_path" => ENV["GEM_PATH"],\n'
    '   "user_var" => ENV["SIM2REAL_USER"], "gem_required" => loaded}\n'
    'end\n'
)

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _partition(ctx) -> str:
    """The session's partition, so an ARN names the partition the check runs in."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(ctx, name, *, reads=3, interval_s=4.0, budget_s=60.0):
    logs = ctx.client("logs")

    def _reap():
        deadline = time.monotonic() + budget_s
        absent = 0
        while absent < reads:
            present = any(g["logGroupName"] == name
                         for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"])
            if present:
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=name)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < reads:
                if time.monotonic() > deadline:
                    raise AssertionError(f"log group {name!r} still present after {budget_s}s")
                time.sleep(interval_s)

    ctx.on_cleanup(_reap)


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data.encode() if isinstance(data, str) else data)
    return buf.getvalue()


def _execution_role(ctx):
    iam = ctx.client("iam")
    policy_arn = _BASIC_EXEC.format(partition=_partition(ctx))
    name = ctx.unique_name("sim2real-l3-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn), "NoSuchEntity"))
    return arn


def _create_retrying(lam, **kwargs):
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] != "InvalidParameterValueException"
                    or err["Message"] != _ROLE_NOT_READY or time.monotonic() > deadline):
                raise
            time.sleep(3)


def _wait_settled(lam, name, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        assert cfg["State"] != "Failed", f"{name} entered State=Failed: {cfg.get('StateReason')!r}"
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        assert time.monotonic() < deadline, (
            f"{name} did not settle within {timeout_s}s: State={cfg['State']!r} "
            f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}")
        time.sleep(1)


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode())
    return resp.get("FunctionError"), json.loads(resp["Payload"].read())


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AWS_EXECUTION_ENV is computed and a guest's Environment Variables cannot shadow it, while
    GEM_PATH is not reserved: a guest override is kept as a prefix with the runtime's own search
    path appended after it, so the function's vendored gem resolves either way.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
    """
    lam = ctx.client("lambda")
    role = _execution_role(ctx)
    fn = ctx.unique_name("sim2real-l3-envov-")
    _reap_log_group(ctx, f"/aws/lambda/{fn}")
    package = _make_zip([
        ("lambda_function.rb", _HANDLER, 0o100644),
        (f"vendor/bundle/ruby/{_API_VERSION}/specifications/{_GEM_NAME}-{_GEM_VERSION}.gemspec",
         _GEMSPEC, 0o100644),
        (f"vendor/bundle/ruby/{_API_VERSION}/gems/{_GEM_NAME}-{_GEM_VERSION}/lib/{_GEM_NAME}.rb",
         _GEM_LIB, 0o100644),
    ])
    _create_retrying(
        lam, FunctionName=fn, Runtime=_RUNTIME, Handler="lambda_function.handler", Role=role,
        Code={"ZipFile": package}, MemorySize=256, Timeout=15, Architectures=["x86_64"],
        Environment={"Variables": {
            "SIM2REAL_USER": "kept",
            "AWS_EXECUTION_ENV": "spoofed-exec-env",
            "GEM_PATH": "/bogus/gem/path",
        }},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    cfg = _wait_settled(lam, fn)
    stored = cfg.get("Environment", {}).get("Variables", {})
    assert stored.get("SIM2REAL_USER") == "kept", f"stored Environment is {stored!r}"

    err, body = _invoke(lam, fn, {})
    assert err is None, f"invoke failed: FunctionError={err!r}, payload {body!r}"
    assert body["user_var"] == "kept", f"the ordinary user variable must pass through; got {body!r}"
    assert body["aws_execution_env"] == f"AWS_Lambda_{_RUNTIME}", (
        f"AWS_EXECUTION_ENV must be the runtime's own computed value, not the guest's "
        f"'spoofed-exec-env' override; got {body['aws_execution_env']!r}")
    guest_prefix = "/bogus/gem/path:"
    vendor_entry = f"/var/task/vendor/bundle/ruby/{_API_VERSION}"
    gem_path = body["gem_path"]
    assert gem_path.startswith(guest_prefix), (
        f"GEM_PATH is not reserved: the guest's override must be KEPT as a prefix; got "
        f"{gem_path!r}")
    assert vendor_entry in gem_path[len(guest_prefix):], (
        f"the runtime's own vendor/bundle search path must still be appended after the guest's "
        f"override; expected {vendor_entry!r} somewhere after the prefix in {gem_path!r}")
    assert body["gem_required"] == "env-gem-ok", (
        f"the vendored gem must still resolve despite the GEM_PATH override attempt; got "
        f"{body['gem_required']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
