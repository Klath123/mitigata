"""The two shared contracts: the normalized event row and the incident JSON."""
from __future__ import annotations

import pyarrow as pa
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- event row
# Every parser emits dicts with (a subset of) these keys; missing keys -> null.
EVENT_FIELDS: list[tuple[str, pa.DataType]] = [
    ("ts", pa.int64()),            # epoch ms UTC
    ("src_file", pa.string()),     # path relative to dataset root
    ("line", pa.int64()),          # 1-based line (or record #) inside src_file
    ("format", pa.string()),       # sniffed format name
    ("host", pa.string()),         # reporting host, upper-cased short name
    ("host_ip", pa.string()),      # reporting host's own IP when the log says so
    ("user", pa.string()),         # normalized account (lower, domain stripped) - used for correlation
    ("user_original", pa.string()),  # account exactly as the log wrote it (DOMAIN\Administrator)
    ("domain", pa.string()),       # account domain: from a domain field or from the account string itself
    ("src_ip", pa.string()),
    ("src_port", pa.int32()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int32()),
    ("dst_host", pa.string()),     # destination hostname when the log names it
    ("src_host", pa.string()),     # source hostname when the log names it (4624 WorkstationName, CEF shost)
    ("proto", pa.string()),
    ("action", pa.string()),       # allow/deny/success/failure/...
    ("event_type", pa.string()),   # namespaced: win:4624, sysmon:1, fw:flow, auth:fail, web:req, audit:execve
    ("type_source", pa.string()),  # how event_type was decided: native | pattern | semantic:<rule> | template | unknown
    ("suggested_event_type", pa.string()),  # unapproved suggestion (AI/template); never used by detection
    ("mapping_confidence", pa.float64()),   # confidence of the suggestion, 0-1
    ("logon_type", pa.int32()),
    ("logon_id", pa.string()),
    ("process", pa.string()),      # full image path or command name
    ("process_guid", pa.string()),
    ("pid", pa.int64()),
    ("ppid", pa.int64()),
    ("parent", pa.string()),
    ("parent_guid", pa.string()),
    ("cmdline", pa.string()),
    ("parent_cmdline", pa.string()),   # Sysmon ParentCommandLine
    ("original_file_name", pa.string()),  # PE OriginalFileName: survives renaming the binary
    ("pe_description", pa.string()),   # PE metadata of the image (Sysmon 1 Description / Company / Product)
    ("pe_company", pa.string()),
    ("pe_product", pa.string()),
    ("hashes", pa.string()),           # Sysmon Hashes / file hash fields
    ("integrity_level", pa.string()),  # Low | Medium | High | System
    ("image_loaded", pa.string()),     # Sysmon 7 ImageLoaded (DLL)
    ("signed", pa.string()),           # signature status of the image / DLL
    ("ticket_encryption", pa.string()),  # Kerberos TicketEncryptionType (0x17 = RC4)
    ("target", pa.string()),       # file / registry key / target process / URL / share / task / service
    ("target_guid", pa.string()),  # Sysmon 10 TargetProcessGuid
    ("target_user", pa.string()),  # account acted on (4720 new user, 4728 member, 4648 explicit creds)
    ("group", pa.string()),        # group name for group membership changes
    ("bytes_out", pa.int64()),
    ("bytes_in", pa.int64()),
    ("status", pa.string()),
    ("severity", pa.string()),     # severity given by the source (e.g. Hayabusa level), if any
    ("rule", pa.string()),         # upstream rule/alert title, if the source carried one
    ("message", pa.string()),      # free text: syslog message, script block, user agent
    ("extra", pa.string()),        # JSON of unmapped fields (kept small)
    ("offset", pa.int64()),        # byte offset of the record in src_file (-1 if not seekable)
    ("parse_status", pa.string()),  # ok | fallback (format parser rejected it, generic parser used) | map_error
    ("parse_error", pa.string()),  # why, when parse_status is not ok
    ("ingest_ts", pa.int64()),     # when AttackStory ingested the record (epoch ms UTC)
    ("ts_assumed", pa.bool_()),    # true if ts relied on an assumption (no timezone in the log and none declared,
                                   # or a syslog date without a year)
    ("raw", pa.string()),          # original record, only stored when offset is -1
]
EVENT_SCHEMA = pa.schema(EVENT_FIELDS)
FIELD_NAMES = [n for n, _ in EVENT_FIELDS]
INT_FIELDS = {n for n, t in EVENT_FIELDS if pa.types.is_integer(t)}
RAW_MAX = 2000


def evidence_id(src_file: str, line: int) -> str:
    """Stable evidence id used everywhere (ground truth, incidents, API)."""
    return f"{src_file}:{line}"


def split_evidence_id(eid: str) -> tuple[str, int]:
    f, _, n = eid.rpartition(":")
    return f, int(n)


# ---------------------------------------------------------------- ATT&CK order
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
TACTIC_INDEX = {t: i for i, t in enumerate(TACTICS)}


# ---------------------------------------------------------------- incident JSON
class Step(BaseModel):
    order: int
    time: str
    ts: int
    host: str | None = None
    user: str | None = None
    technique: str
    sub_technique: str | None = None
    technique_name: str | None = None
    stage: str
    label_source: str = "rule"           # sigma | rule | mapping | suggested
    rule: str | None = None
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    traced: bool = False                 # pulled in by the tracer rather than a hunt hit


class Edge(BaseModel):
    src: str
    dst: str
    kind: str
    confidence: float
    reasons: list[str] = Field(default_factory=list)
    inferred: bool = False


class LookAhead(BaseModel):
    account: str
    can_reach: list[str]
    why: str
    kind: str = "observed admin access"


class Excluded(BaseModel):
    evidence: list[str]
    technique: str | None = None
    host: str | None = None
    user: str | None = None
    reason: str


class Gap(BaseModel):
    host: str
    start: str
    end: str
    expected_events: float
    crosses_edges: list[str] = Field(default_factory=list)


class Sentence(BaseModel):
    text: str
    citations: list[str]
    kind: str = "observed"               # observed | inferred


class Incident(BaseModel):
    incident_id: int
    risk: float
    verdict: str                         # attack | review
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    alerts_merged: int
    stages: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    steps: list[Step] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    hops: list[dict] = Field(default_factory=list)       # {from,to,user,time,evidence}
    graph: dict = Field(default_factory=dict)            # {nodes:[...], edges:[Edge]}
    look_ahead: list[LookAhead] = Field(default_factory=list)
    blast_radius: dict = Field(default_factory=dict)
    excluded: list[Excluded] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    injection_flags: list[dict] = Field(default_factory=list)
    report: list[Sentence] = Field(default_factory=list)
    report_source: str = "template"
    report_url: str = ""
