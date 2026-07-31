"""Secret redaction tests (spec 11.2, 35.1)."""

from ares.redaction import Redactor

R = Redactor()


def test_flag_with_separate_value():
    argv = ["/usr/bin/mysql", "--password", "hunter2", "--host", "db"]
    out, removed = R.redact_argv(argv)
    assert out == ["/usr/bin/mysql", "--password", "[REDACTED]", "--host", "db"]
    assert "argv[2]" in removed
    assert "hunter2" not in " ".join(out)


def test_flag_with_equals():
    out, removed = R.redact_argv(["app", "--token=abc123secret"])
    assert out[1] == "--token=[REDACTED]"
    assert removed == ["argv[1]"]


def test_inline_kv_secret():
    text = "DATABASE_PASSWORD=s3cr3t connecting"
    assert "s3cr3t" not in R.redact_text(text)
    assert "[REDACTED]" in R.redact_text(text)


def test_bearer_token_value_pattern():
    assert "[REDACTED]" in R.redact_text("Authorization: Bearer abcdef0123456789xyz")


def test_aws_key_pattern():
    out = R.redact_text("key AKIAIOSFODNN7EXAMPLE end")
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_connection_string_password_redacted():
    out = R.redact_text("postgres://user:supersecret@db:5432/app")
    assert "supersecret" not in out
    # host/db context preserved
    assert "db:5432" in out


def test_no_false_positive_on_plain_args():
    argv = ["/bin/ls", "-la", "/var/www"]
    out, removed = R.redact_argv(argv)
    assert out == argv
    assert removed == []


def test_env_names_only_excludes_values():
    names = R.env_names_only({"SECRET_KEY": "abc", "PATH": "/usr/bin"})
    assert names == ["PATH", "SECRET_KEY"]
