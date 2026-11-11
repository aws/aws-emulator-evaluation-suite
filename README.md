# AWS Emulator Evaluation Suite

Behavioral fidelity tests for [AWS Emulator](https://docs.aws.amazon.com/emulator/latest/userguide/what-is-service.html),
and a command-line tool that runs them against an emulator endpoint.

This repository is read-only. AI agents author, manage, and maintain it, and populate it with
fidelity tests. It does not accept issues or pull requests. To report a security issue, use the
repository's Security tab.

## Fidelity tests

A fidelity test is a short Python program, `check_<name>.py`, that uses the AWS SDK (boto3). Its
`run(ctx)` function drives a workflow and asserts how AWS behaved: the resulting state of the
resources and, where applicable, the error code and error message. `ctx` is supplied by the runner:
it creates AWS clients for the emulator, names resources uniquely, and registers cleanup. Every
fidelity test was verified against at least two sandboxed AWS accounts, so it asserts real AWS
behavior. Behavior that no fidelity test covers is not verified.

```
behavioral/<service>/check_<name>.py   one fidelity test; <service> is a__b for a cross-service test
behavioral/<service>/deployments/      apps and templates some tests deploy
manifest.jsonl                         one row per test (see below)
docs/TAXONOMY.md                       what each label means
src/, tests/                           the runner (`fidelity_tests_runner`) and its offline tests
```

Each row of `manifest.jsonl` has the test's `check_id` (`<service>.<name>`, the ID in run reports
and published scores), `key` (`<service>/<name>`), `path`, `service`, `operations` (the AWS
operations it calls), `labels`, and `deployments` (the files it deploys).

## Run

Requires [uv](https://docs.astral.sh/uv/) and an AWS Emulator serving AWS on a local HTTPS
endpoint. Some fidelity tests also call command-line tools;
`uv run fidelity-tests-runner requirements <files>` lists what they need.

```bash
uv sync --locked --extra checks

home=$(mktemp -d); HOME=$home aws-emulator -p 4566 & pid=$!
until curl -sk -o /dev/null https://127.0.0.1:4566; do sleep 1; done

uv run fidelity-tests-runner run behavioral/dynamodb/check_update_item_set_list_preserves_element_order.py \
    --endpoint https://127.0.0.1:4566 --emulator-home "$home" --report report.json

kill $pid; wait $pid
```

The emulator writes its access keys and CA certificate under its `HOME`; `--emulator-home` points
the runner at them.

| Verdict | Exit code | Meaning |
|---|---|---|
| `passed` | 0 | every assertion held |
| `failed` | 11 | an assertion failed, or the test timed out |
| `error` | 12 | anything else, e.g. an error the emulator should not return, or a missing tool |

Exit code 2 is an invalid input, reported before anything runs, and 13 a failed cleanup under
`--strict-cleanup`. `uv run fidelity-tests-runner run --help` lists every option.

Each fidelity test times out after 60 s; longer-running tests get 600 s.

To run the whole suite, run each test against its own emulator, since some tests change state an
account has only once, writing each report to one directory; then score them:

```bash
uv run fidelity-tests-runner summarize reports --by-service
```

## Isolation

The runner accepts only a loopback endpoint and signs with the keys the emulator wrote. It runs
each fidelity test without the AWS credentials, profiles, or proxy settings in your environment,
and refuses URLs it builds for a test that point outside the machine or a private network. It
does not restrict the network access of tools and containers a test starts.

## License

[CC0 1.0](LICENSE)
