"""The DNS baseline is set up for a test and torn down with its teardowns, it publishes its
identity's DKIM records, and a module requirement names the full dotted module."""

import threading
import time
from contextlib import contextmanager

import pytest

from fidelity_tests_runner import run as run_module
from fidelity_tests_runner.context import FIXED_CREDS, Context
from fidelity_tests_runner.harness import (
    VERDICT_FAILED,
    VERDICT_PASSED,
    RequiredModuleMissing,
    require_modules,
)
from fidelity_tests_runner.prerequisites import DNS_BASELINE_TAG, prepare_check


class _Route53:
    """A Route 53 client holding hosted zones and their tags."""

    def __init__(self):
        self.zones: dict[str, dict] = {}
        self.tags: dict[str, list] = {}
        self.records: dict[str, set[str]] = {}

    def get_paginator(self, name):
        assert name == "list_hosted_zones"
        zones = list(self.zones.values())

        class _Pages:
            def paginate(self):
                yield {"HostedZones": zones}

        return _Pages()

    def list_tags_for_resource(self, ResourceType, ResourceId):
        return {"ResourceTagSet": {"Tags": self.tags.get(ResourceId, [])}}

    def create_hosted_zone(self, Name, CallerReference):
        zone_id = f"Z{len(self.zones) + 1}"
        self.zones[zone_id] = {"Id": f"/hostedzone/{zone_id}", "Name": f"{Name}.", "Config": {}}
        return {"HostedZone": self.zones[zone_id]}

    def change_tags_for_resource(self, ResourceType, ResourceId, AddTags):
        self.tags.setdefault(ResourceId, []).extend(AddTags)

    def change_resource_record_sets(self, HostedZoneId, ChangeBatch):
        names = self.records.setdefault(HostedZoneId, set())
        for change in ChangeBatch["Changes"]:
            name = change["ResourceRecordSet"]["Name"]
            if change["Action"] == "DELETE":
                names.remove(name)
            else:
                names.add(name)

    def delete_hosted_zone(self, Id):
        assert not self.records.get(Id), "a zone with records is not empty"
        self.zones.pop(Id)


class _SesV2:
    def __init__(self):
        self.identities: set[str] = set()

    def create_email_identity(self, EmailIdentity):
        self.identities.add(EmailIdentity)
        return {"DkimAttributes": {"Tokens": [f"tok-{len(self.identities)}"]}}

    def get_email_identity(self, EmailIdentity):
        held = EmailIdentity in self.identities
        return {
            "DkimAttributes": {"Tokens": ["tok"] if held else []},
            "VerifiedForSendingStatus": held,
        }

    def delete_email_identity(self, EmailIdentity):
        self.identities.remove(EmailIdentity)


def test_a_baseline_is_published_for_the_test_and_deleted_after_it():
    route53, sesv2 = _Route53(), _SesV2()
    clients = {"route53": route53, "sesv2": sesv2}
    with prepare_check(["requires:dns-baseline"], clients.__getitem__):
        (zone_id,) = route53.zones
        (domain,) = sesv2.identities
        assert route53.tags[zone_id] == [DNS_BASELINE_TAG]
        assert {n.split("._domainkey.")[1] for n in route53.records[zone_id]} == {domain}
    assert route53.zones == {} and sesv2.identities == set()


def test_a_baseline_the_emulator_holds_is_used_and_kept():
    route53, sesv2 = _Route53(), _SesV2()
    clients = {"route53": route53, "sesv2": sesv2}
    zone = route53.create_hosted_zone(Name="held.example.net", CallerReference="x")["HostedZone"]
    route53.change_tags_for_resource(
        "hostedzone", zone["Id"].rsplit("/", 1)[-1], [DNS_BASELINE_TAG]
    )
    with prepare_check(["requires:dns-baseline"], clients.__getitem__):
        assert len(route53.zones) == 1 and sesv2.identities == set()
    assert len(route53.zones) == 1


def test_a_failed_setup_is_undone():
    route53, sesv2 = _Route53(), _SesV2()
    clients = {"route53": route53, "sesv2": sesv2}

    def refuse(EmailIdentity):
        raise RuntimeError("identity refused")

    sesv2.create_email_identity = refuse
    with pytest.raises(RuntimeError, match="identity refused"):
        with prepare_check(["requires:dns-baseline"], clients.__getitem__):
            pass
    assert route53.zones == {}


def test_tags_that_need_no_setup_are_ignored():
    with prepare_check(["phase:org", "resource:account-singleton:X Y", "axis:rejection"], None):
        pass


def test_a_failed_baseline_teardown_is_a_cleanup_failure_and_the_verdict_stands(monkeypatch):
    @contextmanager
    def baseline(tags, client_factory, **_):
        yield
        raise RuntimeError("baseline teardown failed")

    monkeypatch.setattr(run_module, "prepare_check", baseline)

    def check(ctx):
        raise AssertionError("differs")

    result = run_module.run_check(
        lambda: Context("http://127.0.0.1:9", creds=FIXED_CREDS),
        "c",
        "g",
        check,
        timeout_s=5,
        cleanup_timeout_s=5,
    )
    assert result.verdict == VERDICT_FAILED
    assert result.cleanup_failed and "baseline teardown failed" in result.cleanup_detail


def test_require_modules_checks_the_full_dotted_name():
    require_modules("fidelity_tests_runner.verdicts")
    with pytest.raises(RequiredModuleMissing):
        require_modules("fidelity_tests_runner.no_such_submodule")
    with pytest.raises(RequiredModuleMissing):
        require_modules("fidelity_tests_runner_no_such_module.child")


def test_a_hung_own_teardown_still_runs_the_baseline_teardown(monkeypatch):
    released = threading.Event()

    @contextmanager
    def baseline(tags, client_factory, **_):
        yield
        released.set()

    monkeypatch.setattr(run_module, "prepare_check", baseline)

    def check(ctx):
        ctx.on_cleanup(lambda: time.sleep(30))

    result = run_module.run_check(
        lambda: Context("http://127.0.0.1:9", creds=FIXED_CREDS),
        "c",
        "g",
        check,
        timeout_s=5,
        cleanup_timeout_s=0.3,
    )
    assert result.verdict == VERDICT_PASSED
    assert released.wait(2), "the tags' setup teardown never ran"
    assert result.cleanup_failed


def test_a_teardown_after_a_body_timeout_sees_the_cleanup_budget():
    seen: dict[str, float | None] = {}

    def check(ctx):
        ctx.on_cleanup(lambda: seen.__setitem__("teardown", ctx.time_left()))
        time.sleep(1.0)
        seen["body"] = ctx.time_left()

    result = run_module.run_check(
        lambda: Context("http://127.0.0.1:9", creds=FIXED_CREDS),
        "c",
        "g",
        check,
        timeout_s=0.2,
        cleanup_timeout_s=40,
    )
    assert result.timed_out
    assert seen["teardown"] is not None and seen["teardown"] > 30
    time.sleep(1.2)
    assert seen["body"] == 0.0


def test_account_email_is_a_fresh_example_address_per_call():
    ctx = Context("http://127.0.0.1:9", creds=FIXED_CREDS)
    first, second = ctx.account_email(), ctx.account_email()
    assert first != second
    assert first.endswith("@example.com") and second.endswith("@example.com")


def test_a_tool_environment_carries_the_cdk_template_endpoint_and_js_sdk_preload():
    ctx = Context("http://127.0.0.1:9", creds=FIXED_CREDS)
    try:
        env = ctx.subprocess_env()
        assert env["AWS_ENDPOINT_URL_S3_FOR_CLOUDFORMATION"] == "http://127.0.0.1:9"
        assert env["SAM_CLI_TELEMETRY"] == "0"
        preload = env["NODE_OPTIONS"].removeprefix('--require "').removesuffix('"')
        with open(preload, encoding="utf-8") as fh:
            assert "aws-sdk/global" in fh.read()
        assert preload.startswith(env["TMPDIR"])
    finally:
        ctx.run_cleanups()


def test_a_long_tmpdir_base_falls_back_to_tmp(monkeypatch):
    from fidelity_tests_runner import context as context_module

    monkeypatch.setattr(context_module.tempfile, "gettempdir", lambda: "/x" * 40)
    assert context_module.socket_safe_tmp_base() == "/tmp"
    monkeypatch.setattr(context_module.tempfile, "gettempdir", lambda: "/tmp")
    assert context_module.socket_safe_tmp_base() is None


def test_emulator_clients_pin_off_endpoint_rulesets_and_sign_s3_express_control_without_session():
    ctx = Context("http://127.0.0.1:9", creds=FIXED_CREDS)
    sent: list[str] = []

    def capture(request, **_):
        sent.append(request.url)
        raise RuntimeError("captured")

    signin, s3 = ctx.client("signin"), ctx.client("s3")
    for client in (signin, s3):
        client.meta.events.register_last("before-send", capture)
    with pytest.raises(RuntimeError, match="captured"):
        signin.get_console_authorization_configuration()
    assert sent[-1].startswith("http://127.0.0.1:9/")
    with pytest.raises(RuntimeError, match="captured"):
        s3.create_bucket(
            Bucket="b--usw2-az1--x-s3",
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": "usw2-az1"},
                "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
            },
        )
    assert sent[-1].startswith("http://127.0.0.1:9/") and "session" not in sent[-1]


def test_a_context_whose_start_deadline_takes_no_this_thread_still_runs():
    """A caller's own context with ``start_deadline(budget_s)`` keeps one budget, no TypeError."""

    class OwnContext(Context):
        def start_deadline(self, budget_s):  # the older signature
            super().start_deadline(budget_s)

    torn_down = []

    def check(ctx):
        ctx.on_cleanup(lambda: torn_down.append(ctx.time_left()))

    result = run_module.run_check(
        lambda: OwnContext("http://127.0.0.1:9", creds=FIXED_CREDS), "c", "g", check, timeout_s=5
    )
    assert result.verdict == VERDICT_PASSED and not result.runner_fault
    assert torn_down and torn_down[0] is not None
