"""Typed configuration model mirroring the YAML in spec section 27."""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, Field


class ResponseMode(str, enum.Enum):
    OBSERVE = "observe"
    ALERT = "alert"
    APPROVE = "approve"
    AUTOMATIC = "automatic"
    # spec 27 uses "recommend" as the response.mode value for the approve model.
    RECOMMEND = "recommend"


class HostConfig(BaseModel):
    role: str = "generic"
    environment: str = "production"
    criticality: Literal["low", "medium", "high", "critical"] = "medium"


class DaemonConfig(BaseModel):
    enabled: bool = True
    event_buffer_size: int = 65536
    batch_size: int = 250
    flush_interval_ms: int = 250


class SensorToggle(BaseModel):
    enabled: bool = True


class FilesystemSensorConfig(SensorToggle):
    protected_paths: list[str] = Field(
        default_factory=lambda: [
            "/etc",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/boot",
            "/var/spool/cron",
            "/etc/cron.d",
            "/etc/systemd",
            "/home/*/.ssh",
            "/root/.ssh",
            "/opt",
        ]
    )
    ignored_paths: list[str] = Field(default_factory=lambda: ["/var/log", "/tmp/application-cache"])


class SensorsConfig(BaseModel):
    process: SensorToggle = Field(default_factory=SensorToggle)
    network: SensorToggle = Field(default_factory=SensorToggle)
    filesystem: FilesystemSensorConfig = Field(default_factory=FilesystemSensorConfig)
    identity: SensorToggle = Field(default_factory=SensorToggle)
    containers: SensorToggle = Field(default_factory=lambda: SensorToggle(enabled=False))


class InvestigationConfig(BaseModel):
    enabled: bool = True
    interval_seconds: int = 60
    timeout_seconds: int = 90
    max_cases_per_cycle: int = 10
    max_tool_calls_per_case: int = 12
    max_input_tokens: int = 24000
    max_output_tokens: int = 4000
    # Default provider is OpenRouter (OpenAI-compatible): users pick any model
    # with two env vars — OPENROUTER_API_KEY and OPENROUTER_MODEL. Other values:
    # "openai" (or any OpenAI-compatible base_url), "anthropic", "local".
    # If credentials are missing the investigator falls back to "local" so the
    # pipeline never stops producing verdicts (spec §25.2).
    model_provider: str = "openrouter"
    # Empty means "read from the provider's env var" (e.g. OPENROUTER_MODEL).
    model: str = ""
    access_mode: Literal["read_only", "read_write"] = "read_only"


class DetectionConfig(BaseModel):
    immediate_alert_threshold: float = 0.90
    investigation_threshold: float = 0.60
    retain_threshold: float = 0.30
    learning_period_days: int = 7


class ResponseConfig(BaseModel):
    mode: ResponseMode = ResponseMode.RECOMMEND
    automatic_actions: list[str] = Field(
        default_factory=lambda: ["capture_process_state", "hash_file", "preserve_logs"]
    )
    approval_required: list[str] = Field(
        default_factory=lambda: [
            "stop_process",
            "isolate_container",
            "block_destination",
            "disable_user",
        ]
    )
    prohibited: list[str] = Field(
        default_factory=lambda: ["delete_file", "execute_generated_shell_command"]
    )


class StorageConfig(BaseModel):
    engine: Literal["sqlite"] = "sqlite"
    path: str = "/var/lib/ares/ares.db"
    raw_event_retention_hours: int = 24
    medium_risk_retention_days: int = 7
    high_risk_retention_days: int = 30
    case_event_retention_days: int = 90
    investigation_retention_days: int = 365


class PrivacyConfig(BaseModel):
    redact_secrets: bool = True
    send_raw_logs_to_model: bool = False
    send_file_contents_to_model: bool = False
    include_command_arguments: Literal["full", "redacted", "none"] = "redacted"


class BudgetsConfig(BaseModel):
    max_cases_per_minute: int = 10
    max_ai_calls_per_hour: int = 120
    max_cost_per_day_usd: float = 20.0
    critical_cases_bypass_hourly_limit: bool = True


class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    username: str | None = None
    password: str | None = None  # prefer ARES_SMTP_PASSWORD env over config
    use_tls: bool = True
    from_addr: str | None = None
    to_addrs: list[str] = Field(default_factory=list)


class PagerDutyConfig(BaseModel):
    enabled: bool = False
    routing_key: str | None = None  # prefer ARES_PAGERDUTY_ROUTING_KEY env
    # Only page at or above this severity — pages are expensive; default to the
    # most urgent band so on-call is not woken for routine findings.
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "critical"


class NotificationsConfig(BaseModel):
    """Where and when to notify humans about incidents (spec §21, §27).

    Every channel is push-only (outbound HTTPS/SMTP) so nothing inbound needs to
    be exposed on the host. Secrets are read from env vars in preference to the
    config file. ``min_severity`` gates all channels except PagerDuty, which has
    its own higher threshold, to avoid alert fatigue.
    """

    console: bool = True
    # Global floor: findings/verdicts below this severity are not sent anywhere.
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    # Slack incoming webhook URL (or ARES_SLACK_WEBHOOK env).
    slack_webhook: str | None = None
    # Generic JSON webhook — route to anything (or ARES_NOTIFY_WEBHOOK env).
    webhook: str | None = None
    email: EmailConfig = Field(default_factory=EmailConfig)
    pagerduty: PagerDutyConfig = Field(default_factory=PagerDutyConfig)


class Config(BaseModel):
    version: int = 1
    host: HostConfig = Field(default_factory=HostConfig)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    sensors: SensorsConfig = Field(default_factory=SensorsConfig)
    investigation: InvestigationConfig = Field(default_factory=InvestigationConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    budgets: BudgetsConfig = Field(default_factory=BudgetsConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)

    model_config = {"use_enum_values": True}
