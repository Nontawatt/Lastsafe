# Label System Design for Data Classification
## Restic Central Server Integration

---

## 1. Overview

ระบบ Label สำหรับ Data Classification ที่ออกแบบมาเพื่อทำงานร่วมกับ Restic Central Server โดยมีวัตถุประสงค์หลัก:

- **จำแนกประเภทข้อมูล** ตามระดับความสำคัญและความลับ
- **ควบคุมการเข้าถึง** ตาม label ที่กำหนด
- **ติดตาม metadata** ของไฟล์ที่ backup
- **รองรับ compliance** ตามมาตรฐาน (PDPA, GDPR, ISO 27001)

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RESTIC CENTRAL SERVER                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   REST API   │────│ Label Engine │────│  PostgreSQL  │          │
│  │   Gateway    │    │   Service    │    │   Database   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│         │                   │                   │                   │
│         │            ┌──────┴──────┐            │                   │
│         │            │             │            │                   │
│  ┌──────▼──────┐  ┌──▼───┐  ┌─────▼────┐  ┌───▼────┐              │
│  │   Restic    │  │Policy│  │  Audit   │  │ Label  │              │
│  │  Backend    │  │Engine│  │  Logger  │  │ Cache  │              │
│  └─────────────┘  └──────┘  └──────────┘  └────────┘              │
│         │                                                           │
│  ┌──────▼──────────────────────────────────────────┐               │
│  │              RESTIC REPOSITORIES                 │               │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐         │               │
│  │  │ Repo 1  │  │ Repo 2  │  │ Repo N  │         │               │
│  │  │(Public) │  │(Internal│  │(Secret) │         │               │
│  │  └─────────┘  └─────────┘  └─────────┘         │               │
│  └─────────────────────────────────────────────────┘               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Client A    │    │   Client B    │    │   Client N    │
│ (Lastsafe +   │    │ (Restic CLI)  │    │ (Web UI)      │
│  Restic)      │    │               │    │               │
└───────────────┘    └───────────────┘    └───────────────┘
```

---

## 3. Data Classification Levels

### 3.1 ระดับการจำแนกข้อมูล (Classification Tiers)

| Level | Label | คำอธิบาย | ตัวอย่าง | Retention |
|-------|-------|----------|----------|-----------|
| **L0** | `PUBLIC` | ข้อมูลสาธารณะ | เอกสารเผยแพร่, Marketing | 1 ปี |
| **L1** | `INTERNAL` | ข้อมูลภายในองค์กร | คู่มือ, Policies | 3 ปี |
| **L2** | `CONFIDENTIAL` | ข้อมูลลับ | รายงานการเงิน, สัญญา | 5 ปี |
| **L3** | `SECRET` | ข้อมูลลับสูง | ข้อมูลลูกค้า, PII | 7 ปี |
| **L4** | `TOP_SECRET` | ข้อมูลลับสุดยอด | กุญแจเข้ารหัส, Credentials | 10 ปี |

### 3.2 Label Categories

```yaml
label_categories:
  # ระดับความลับ (Security Classification)
  security:
    - PUBLIC
    - INTERNAL
    - CONFIDENTIAL
    - SECRET
    - TOP_SECRET

  # ประเภทข้อมูล (Data Type)
  data_type:
    - PERSONAL_DATA      # ข้อมูลส่วนบุคคล (PDPA)
    - FINANCIAL          # ข้อมูลการเงิน
    - MEDICAL            # ข้อมูลสุขภาพ
    - LEGAL              # เอกสารกฎหมาย
    - TECHNICAL          # เอกสารเทคนิค
    - OPERATIONAL        # ข้อมูลปฏิบัติการ

  # แหล่งที่มา (Source)
  source:
    - CUSTOMER           # จากลูกค้า
    - VENDOR             # จาก vendor
    - INTERNAL           # สร้างภายใน
    - GOVERNMENT         # จากหน่วยงานรัฐ

  # การปฏิบัติตามกฎหมาย (Compliance)
  compliance:
    - PDPA               # พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล
    - GDPR               # EU General Data Protection
    - HIPAA              # สำหรับข้อมูลสุขภาพ
    - PCI_DSS            # สำหรับข้อมูลบัตรเครดิต
    - ISO27001           # มาตรฐานความปลอดภัย

  # สถานะ (Status)
  status:
    - ACTIVE             # ใช้งานอยู่
    - ARCHIVED           # เก็บถาวร
    - PENDING_DELETION   # รอลบ
    - LEGAL_HOLD         # ห้ามลบ (คดีความ)
```

---

## 4. Database Schema

### 4.1 Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     clients     │       │   repositories  │       │    snapshots    │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id (PK)         │──┐    │ id (PK)         │──┐    │ id (PK)         │
│ name            │  │    │ client_id (FK)  │◄─┘    │ repo_id (FK)    │◄─┐
│ hostname        │  └───►│ name            │       │ restic_id       │  │
│ api_key_hash    │       │ path            │       │ timestamp       │  │
│ created_at      │       │ default_label   │       │ hostname        │  │
└─────────────────┘       │ encryption_key  │       │ tags            │  │
                          └─────────────────┘       └─────────────────┘  │
                                                                         │
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐  │
│     labels      │       │   file_labels   │       │   file_index    │  │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤  │
│ id (PK)         │──┐    │ id (PK)         │       │ id (PK)         │  │
│ name            │  │    │ file_id (FK)    │◄──────│ snapshot_id(FK) │──┘
│ category        │  │    │ label_id (FK)   │◄─┐    │ path            │
│ color           │  └────┼─────────────────┤  │    │ size            │
│ priority        │       │ assigned_by     │  │    │ hash            │
│ description     │       │ assigned_at     │  │    │ mtime           │
│ retention_days  │       │ expires_at      │  │    │ mode            │
│ requires_encrypt│       └─────────────────┘  │    └─────────────────┘
│ created_at      │                            │
└─────────────────┘                            │
                                               │
┌─────────────────┐       ┌─────────────────┐  │
│  label_rules    │       │   audit_logs    │  │
├─────────────────┤       ├─────────────────┤  │
│ id (PK)         │       │ id (PK)         │  │
│ name            │       │ timestamp       │  │
│ pattern         │       │ action          │  │
│ label_id (FK)   │───────┼─────────────────┤  │
│ priority        │       │ label_id (FK)   │──┘
│ auto_apply      │       │ file_id (FK)    │
│ created_at      │       │ user_id         │
└─────────────────┘       │ details (JSON)  │
                          └─────────────────┘
```

### 4.2 SQL Schema

```sql
-- ตาราง clients: เก็บข้อมูล backup clients
CREATE TABLE clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    api_key_hash    VARCHAR(64) NOT NULL,
    allowed_labels  TEXT[],  -- labels ที่ client นี้สามารถใช้ได้
    max_retention   INTEGER DEFAULT 365,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(hostname)
);

-- ตาราง repositories: Restic repositories
CREATE TABLE repositories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID REFERENCES clients(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    path            TEXT NOT NULL,
    default_label   VARCHAR(50) DEFAULT 'INTERNAL',
    encryption_key  TEXT,  -- encrypted with master key
    storage_quota   BIGINT,  -- bytes
    current_size    BIGINT DEFAULT 0,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(client_id, name)
);

-- ตาราง labels: นิยาม labels ทั้งหมด
CREATE TABLE labels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(50) NOT NULL UNIQUE,
    category        VARCHAR(50) NOT NULL,
    display_name    VARCHAR(100),
    color           VARCHAR(7) DEFAULT '#808080',  -- hex color
    icon            VARCHAR(50),
    priority        INTEGER DEFAULT 0,  -- higher = more restrictive
    description     TEXT,

    -- Policies
    retention_days  INTEGER DEFAULT 365,
    requires_encryption BOOLEAN DEFAULT FALSE,
    requires_approval   BOOLEAN DEFAULT FALSE,
    allowed_roles   TEXT[],  -- roles ที่สามารถเข้าถึงได้

    -- Metadata
    is_system       BOOLEAN DEFAULT FALSE,  -- system labels ลบไม่ได้
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    created_by      UUID
);

-- ตาราง snapshots: Restic snapshots
CREATE TABLE snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id         UUID REFERENCES repositories(id) ON DELETE CASCADE,
    restic_id       VARCHAR(64) NOT NULL,  -- restic snapshot ID
    short_id        VARCHAR(8),
    timestamp       TIMESTAMPTZ NOT NULL,
    hostname        VARCHAR(255),
    username        VARCHAR(255),
    paths           TEXT[],
    tags            TEXT[],
    total_size      BIGINT,
    total_files     INTEGER,
    parent_id       VARCHAR(64),  -- parent snapshot
    created_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(repo_id, restic_id)
);

-- ตาราง file_index: index ไฟล์ใน snapshot
CREATE TABLE file_index (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id     UUID REFERENCES snapshots(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    name            VARCHAR(255),
    size            BIGINT,
    hash            VARCHAR(64),  -- SHA-256
    mtime           TIMESTAMPTZ,
    mode            VARCHAR(10),
    uid             INTEGER,
    gid             INTEGER,
    inode           BIGINT,
    content_type    VARCHAR(100),

    -- Indexing
    path_tokens     TSVECTOR,  -- for full-text search

    CONSTRAINT unique_file_per_snapshot UNIQUE(snapshot_id, path)
);

-- ตาราง file_labels: mapping ระหว่าง files และ labels
CREATE TABLE file_labels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID REFERENCES file_index(id) ON DELETE CASCADE,
    label_id        UUID REFERENCES labels(id) ON DELETE CASCADE,

    -- Assignment metadata
    assigned_by     UUID,  -- user or system
    assigned_at     TIMESTAMPTZ DEFAULT NOW(),
    assignment_type VARCHAR(20) DEFAULT 'manual',  -- manual, auto, inherited
    confidence      FLOAT,  -- for ML-based classification

    -- Expiration
    expires_at      TIMESTAMPTZ,

    UNIQUE(file_id, label_id)
);

-- ตาราง label_rules: กฎสำหรับ auto-labeling
CREATE TABLE label_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,

    -- Matching criteria
    pattern_type    VARCHAR(20) NOT NULL,  -- path, extension, content, regex
    pattern         TEXT NOT NULL,

    -- Action
    label_id        UUID REFERENCES labels(id) ON DELETE CASCADE,
    priority        INTEGER DEFAULT 0,  -- higher priority wins

    -- Scope
    repo_id         UUID REFERENCES repositories(id),  -- NULL = all repos
    auto_apply      BOOLEAN DEFAULT TRUE,

    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    created_by      UUID
);

-- ตาราง audit_logs: บันทึกการเปลี่ยนแปลง
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ DEFAULT NOW(),

    -- Who
    user_id         UUID,
    client_id       UUID REFERENCES clients(id),
    ip_address      INET,

    -- What
    action          VARCHAR(50) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     UUID,

    -- Details
    old_value       JSONB,
    new_value       JSONB,
    details         JSONB
);

-- Indexes for performance
CREATE INDEX idx_file_index_snapshot ON file_index(snapshot_id);
CREATE INDEX idx_file_index_path ON file_index USING gin(path_tokens);
CREATE INDEX idx_file_labels_file ON file_labels(file_id);
CREATE INDEX idx_file_labels_label ON file_labels(label_id);
CREATE INDEX idx_snapshots_repo ON snapshots(repo_id);
CREATE INDEX idx_snapshots_timestamp ON snapshots(timestamp);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Insert default labels
INSERT INTO labels (name, category, display_name, color, priority, retention_days, requires_encryption, is_system) VALUES
('PUBLIC',       'security', 'Public',       '#4CAF50', 0,  365,  FALSE, TRUE),
('INTERNAL',     'security', 'Internal',     '#2196F3', 1,  1095, FALSE, TRUE),
('CONFIDENTIAL', 'security', 'Confidential', '#FF9800', 2,  1825, TRUE,  TRUE),
('SECRET',       'security', 'Secret',       '#F44336', 3,  2555, TRUE,  TRUE),
('TOP_SECRET',   'security', 'Top Secret',   '#9C27B0', 4,  3650, TRUE,  TRUE),
('PERSONAL_DATA','data_type','Personal Data','#E91E63', 2,  2555, TRUE,  TRUE),
('FINANCIAL',    'data_type','Financial',    '#009688', 2,  2555, TRUE,  TRUE),
('PDPA',         'compliance','PDPA',        '#673AB7', 3,  2555, TRUE,  TRUE),
('GDPR',         'compliance','GDPR',        '#3F51B5', 3,  2555, TRUE,  TRUE);
```

---

## 5. API Design

### 5.1 REST API Endpoints

```yaml
# Label Management APIs
labels:
  # List all labels
  GET /api/v1/labels:
    query:
      category: string  # filter by category
      active: boolean
    response: Label[]

  # Create new label
  POST /api/v1/labels:
    body:
      name: string
      category: string
      color: string
      retention_days: integer
      requires_encryption: boolean
    response: Label

  # Get label details
  GET /api/v1/labels/{label_id}:
    response: Label

  # Update label
  PUT /api/v1/labels/{label_id}:
    body: Partial<Label>
    response: Label

  # Delete label (soft delete)
  DELETE /api/v1/labels/{label_id}:
    response: { success: boolean }

# File Labeling APIs
file_labels:
  # Get labels for a file
  GET /api/v1/files/{file_id}/labels:
    response: Label[]

  # Assign label to file
  POST /api/v1/files/{file_id}/labels:
    body:
      label_id: uuid
      expires_at: datetime (optional)
    response: FileLabel

  # Remove label from file
  DELETE /api/v1/files/{file_id}/labels/{label_id}:
    response: { success: boolean }

  # Bulk label assignment
  POST /api/v1/labels/bulk-assign:
    body:
      file_ids: uuid[]
      label_id: uuid
    response: { assigned: integer, failed: integer }

# Search & Query APIs
search:
  # Search files by labels
  GET /api/v1/search/files:
    query:
      labels: string[]     # label names
      path: string         # path pattern
      repo_id: uuid
      snapshot_id: uuid
      min_size: integer
      max_size: integer
      after: datetime
      before: datetime
    response:
      files: FileInfo[]
      total: integer

  # Get label statistics
  GET /api/v1/stats/labels:
    query:
      repo_id: uuid
    response:
      by_label: { label: string, count: integer, size: integer }[]
      by_category: { category: string, count: integer }[]

# Label Rules APIs
rules:
  # List rules
  GET /api/v1/label-rules:
    response: LabelRule[]

  # Create rule
  POST /api/v1/label-rules:
    body:
      name: string
      pattern_type: "path" | "extension" | "content" | "regex"
      pattern: string
      label_id: uuid
      priority: integer
    response: LabelRule

  # Apply rules to existing files
  POST /api/v1/label-rules/apply:
    body:
      repo_id: uuid
      snapshot_id: uuid (optional)
      dry_run: boolean
    response:
      would_apply: integer
      applied: integer

# Restic Integration APIs
restic:
  # Register new snapshot with labels
  POST /api/v1/restic/snapshots:
    body:
      repo_id: uuid
      restic_snapshot_id: string
      default_label: string
    response: Snapshot

  # Get snapshot with label summary
  GET /api/v1/restic/snapshots/{snapshot_id}:
    response:
      snapshot: Snapshot
      label_summary: { label: string, count: integer }[]

  # Index files from snapshot
  POST /api/v1/restic/snapshots/{snapshot_id}/index:
    body:
      apply_rules: boolean
    response:
      indexed: integer
      labeled: integer
```

### 5.2 API Response Types

```typescript
interface Label {
  id: string;
  name: string;
  category: string;
  display_name: string;
  color: string;
  icon?: string;
  priority: number;
  description?: string;
  retention_days: number;
  requires_encryption: boolean;
  requires_approval: boolean;
  allowed_roles: string[];
  is_system: boolean;
  is_active: boolean;
  created_at: string;
}

interface FileInfo {
  id: string;
  snapshot_id: string;
  path: string;
  name: string;
  size: number;
  hash: string;
  mtime: string;
  mode: string;
  content_type?: string;
  labels: Label[];
}

interface LabelRule {
  id: string;
  name: string;
  description?: string;
  pattern_type: 'path' | 'extension' | 'content' | 'regex';
  pattern: string;
  label: Label;
  priority: number;
  repo_id?: string;
  auto_apply: boolean;
  is_active: boolean;
}

interface Snapshot {
  id: string;
  repo_id: string;
  restic_id: string;
  short_id: string;
  timestamp: string;
  hostname: string;
  paths: string[];
  tags: string[];
  total_size: number;
  total_files: number;
}
```

---

## 6. Label Rules Engine

### 6.1 Rule Pattern Examples

```yaml
# Auto-label by file extension
extension_rules:
  - name: "PDF Documents"
    pattern_type: extension
    pattern: ".pdf"
    label: INTERNAL

  - name: "Source Code"
    pattern_type: extension
    pattern: ".py,.js,.ts,.go,.java"
    label: INTERNAL

  - name: "Database Files"
    pattern_type: extension
    pattern: ".sql,.db,.sqlite"
    label: CONFIDENTIAL

# Auto-label by path pattern
path_rules:
  - name: "Customer Data"
    pattern_type: path
    pattern: "**/customers/**"
    label: PERSONAL_DATA

  - name: "Financial Reports"
    pattern_type: path
    pattern: "**/finance/**/*.xlsx"
    label: FINANCIAL

  - name: "Credentials"
    pattern_type: path
    pattern: "**/.env,**/credentials/**,**/*.pem,**/*.key"
    label: TOP_SECRET

# Auto-label by regex
regex_rules:
  - name: "Thai ID Card Numbers"
    pattern_type: regex
    pattern: '\b[0-9]{13}\b'
    label: PERSONAL_DATA

  - name: "Credit Card Numbers"
    pattern_type: regex
    pattern: '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'
    label: CONFIDENTIAL

  - name: "Email Addresses (bulk)"
    pattern_type: regex
    pattern: '(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}){10,}'
    label: PERSONAL_DATA
```

### 6.2 Rule Processing Logic

```python
class LabelRuleEngine:
    """Engine สำหรับประมวลผล label rules"""

    def __init__(self, db_session):
        self.db = db_session
        self.rules_cache = {}

    def load_rules(self, repo_id: Optional[str] = None) -> List[LabelRule]:
        """โหลด rules ที่ active ทั้งหมด เรียงตาม priority"""
        query = self.db.query(LabelRule).filter(
            LabelRule.is_active == True
        )
        if repo_id:
            query = query.filter(
                or_(LabelRule.repo_id == repo_id, LabelRule.repo_id == None)
            )
        return query.order_by(LabelRule.priority.desc()).all()

    def match_file(self, file_info: FileInfo) -> List[LabelMatch]:
        """หา labels ที่ match กับ file"""
        matches = []
        rules = self.load_rules(file_info.repo_id)

        for rule in rules:
            if self._check_match(rule, file_info):
                matches.append(LabelMatch(
                    label_id=rule.label_id,
                    rule_id=rule.id,
                    confidence=1.0,
                    assignment_type='auto'
                ))

        return matches

    def _check_match(self, rule: LabelRule, file: FileInfo) -> bool:
        """ตรวจสอบว่า file match กับ rule หรือไม่"""
        if rule.pattern_type == 'extension':
            extensions = rule.pattern.split(',')
            return any(file.path.endswith(ext.strip()) for ext in extensions)

        elif rule.pattern_type == 'path':
            import fnmatch
            patterns = rule.pattern.split(',')
            return any(fnmatch.fnmatch(file.path, p.strip()) for p in patterns)

        elif rule.pattern_type == 'regex':
            import re
            # สำหรับ regex ต้องอ่าน content (ถ้าต้องการ)
            return bool(re.search(rule.pattern, file.path))

        return False

    def apply_to_snapshot(
        self,
        snapshot_id: str,
        dry_run: bool = False
    ) -> Dict[str, int]:
        """Apply rules to all files in a snapshot"""
        files = self.db.query(FileIndex).filter(
            FileIndex.snapshot_id == snapshot_id
        ).all()

        stats = {'matched': 0, 'applied': 0, 'skipped': 0}

        for file in files:
            matches = self.match_file(file)
            for match in matches:
                stats['matched'] += 1
                if not dry_run:
                    self._apply_label(file.id, match)
                    stats['applied'] += 1

        return stats
```

---

## 7. Restic Integration

### 7.1 Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LABEL-AWARE RESTIC FLOW                   │
└─────────────────────────────────────────────────────────────┘

  [Client]                    [Central Server]                [Storage]
     │                              │                            │
     │  1. restic backup            │                            │
     │  --tag "label:INTERNAL"      │                            │
     │─────────────────────────────>│                            │
     │                              │  2. Store snapshot         │
     │                              │─────────────────────────────>
     │                              │                            │
     │  3. POST /api/v1/restic/     │                            │
     │     snapshots                │                            │
     │─────────────────────────────>│                            │
     │                              │  4. Index files            │
     │                              │  5. Apply label rules      │
     │                              │  6. Store metadata         │
     │                              │                            │
     │  7. Response: Snapshot +     │                            │
     │     Label Summary            │                            │
     │<─────────────────────────────│                            │
     │                              │                            │
```

### 7.2 Restic Hook Scripts

```bash
#!/bin/bash
# /etc/restic/hooks/post-backup.sh
# Hook script ที่รันหลัง backup เสร็จ

RESTIC_CENTRAL_API="https://backup-server.example.com/api/v1"
API_KEY="${RESTIC_API_KEY}"

# Get the latest snapshot ID
SNAPSHOT_ID=$(restic snapshots --json --last 1 | jq -r '.[0].id')
REPO_ID="${RESTIC_REPO_ID}"
DEFAULT_LABEL="${BACKUP_LABEL:-INTERNAL}"

# Register snapshot with central server
curl -X POST "${RESTIC_CENTRAL_API}/restic/snapshots" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"repo_id\": \"${REPO_ID}\",
    \"restic_snapshot_id\": \"${SNAPSHOT_ID}\",
    \"default_label\": \"${DEFAULT_LABEL}\"
  }"

# Index files and apply rules
curl -X POST "${RESTIC_CENTRAL_API}/restic/snapshots/${SNAPSHOT_ID}/index" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"apply_rules": true}'

echo "Snapshot ${SNAPSHOT_ID} registered and indexed with labels"
```

### 7.3 Restic REST Server Configuration

```toml
# /etc/restic/server.toml
# Configuration for restic REST server with label integration

[server]
listen = "0.0.0.0:8000"
path = "/srv/restic/repos"
tls = true
tls_cert = "/etc/restic/certs/server.crt"
tls_key = "/etc/restic/certs/server.key"

[authentication]
htpasswd = "/etc/restic/htpasswd"

[hooks]
# เรียก label server หลัง operations
post_backup = "/etc/restic/hooks/post-backup.sh"
post_restore = "/etc/restic/hooks/post-restore.sh"

[label_server]
# Integration กับ label system
enabled = true
url = "http://localhost:8080/api/v1"
api_key_env = "LABEL_API_KEY"

# Enforce labels
require_label = true
allowed_labels = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]
default_label = "INTERNAL"

[retention]
# Retention ตาม label
use_label_retention = true
fallback_days = 30

[access_control]
# ควบคุมการเข้าถึงตาม label
enforce_label_acl = true
```

---

## 8. Security Considerations

### 8.1 Access Control Matrix

| Action | PUBLIC | INTERNAL | CONFIDENTIAL | SECRET | TOP_SECRET |
|--------|--------|----------|--------------|--------|------------|
| View metadata | All Users | Internal | Manager+ | Director+ | Admin Only |
| Download | All Users | Internal | Approval | Approval | Admin Only |
| Modify labels | Admin | Admin | Admin | Admin | Super Admin |
| Delete | - | Admin | Director+ | Admin | Super Admin |
| Export | All Users | Internal | Approval | Denied | Denied |

### 8.2 Security Implementation

```python
class LabelAccessControl:
    """ควบคุมการเข้าถึงตาม label"""

    ROLE_HIERARCHY = {
        'user': 0,
        'internal': 1,
        'manager': 2,
        'director': 3,
        'admin': 4,
        'super_admin': 5
    }

    LABEL_REQUIREMENTS = {
        'PUBLIC': 'user',
        'INTERNAL': 'internal',
        'CONFIDENTIAL': 'manager',
        'SECRET': 'director',
        'TOP_SECRET': 'admin'
    }

    def can_access(self, user: User, file: FileInfo) -> bool:
        """ตรวจสอบว่า user สามารถเข้าถึง file ได้หรือไม่"""
        user_level = self.ROLE_HIERARCHY.get(user.role, 0)

        # หา label ที่ restrictive ที่สุดของ file
        max_required_level = 0
        for label in file.labels:
            required_role = self.LABEL_REQUIREMENTS.get(label.name, 'user')
            required_level = self.ROLE_HIERARCHY.get(required_role, 0)
            max_required_level = max(max_required_level, required_level)

        return user_level >= max_required_level

    def filter_accessible_files(
        self,
        user: User,
        files: List[FileInfo]
    ) -> List[FileInfo]:
        """กรองเฉพาะ files ที่ user เข้าถึงได้"""
        return [f for f in files if self.can_access(user, f)]
```

### 8.3 Audit Trail

```python
class AuditLogger:
    """บันทึก audit log สำหรับทุก operation ที่เกี่ยวกับ labels"""

    def log_label_assigned(
        self,
        file_id: str,
        label_id: str,
        user_id: str,
        assignment_type: str
    ):
        self.db.add(AuditLog(
            action='LABEL_ASSIGNED',
            resource_type='file',
            resource_id=file_id,
            user_id=user_id,
            details={
                'label_id': label_id,
                'assignment_type': assignment_type
            }
        ))

    def log_file_accessed(
        self,
        file_id: str,
        user_id: str,
        access_type: str,
        labels: List[str]
    ):
        self.db.add(AuditLog(
            action='FILE_ACCESSED',
            resource_type='file',
            resource_id=file_id,
            user_id=user_id,
            details={
                'access_type': access_type,
                'file_labels': labels
            }
        ))
```

---

## 9. Implementation Phases

### Phase 1: Core Label System (สัปดาห์ที่ 1-2)
- [ ] Database schema setup
- [ ] Label CRUD APIs
- [ ] Basic file labeling
- [ ] Unit tests

### Phase 2: Rules Engine (สัปดาห์ที่ 3-4)
- [ ] Rule definition system
- [ ] Pattern matching (path, extension, regex)
- [ ] Auto-labeling on backup
- [ ] Rule management APIs

### Phase 3: Restic Integration (สัปดาห์ที่ 5-6)
- [ ] Restic REST server hooks
- [ ] Snapshot registration
- [ ] File indexing
- [ ] Label-based retention

### Phase 4: Access Control (สัปดาห์ที่ 7-8)
- [ ] Role-based access control
- [ ] Label-based permissions
- [ ] Audit logging
- [ ] Compliance reports

### Phase 5: Advanced Features (สัปดาห์ที่ 9-10)
- [ ] ML-based classification
- [ ] Content scanning
- [ ] Bulk operations
- [ ] Dashboard & analytics

---

## 10. File Structure

```
lastsafe/
├── label_server/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Configuration
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── labels.py           # Label CRUD endpoints
│   │   ├── files.py            # File labeling endpoints
│   │   ├── rules.py            # Label rules endpoints
│   │   ├── search.py           # Search endpoints
│   │   ├── restic.py           # Restic integration endpoints
│   │   └── auth.py             # Authentication
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── label.py            # Label model
│   │   ├── file.py             # File index model
│   │   ├── rule.py             # Label rule model
│   │   ├── snapshot.py         # Snapshot model
│   │   └── audit.py            # Audit log model
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── label_service.py    # Label business logic
│   │   ├── rule_engine.py      # Rule processing
│   │   ├── restic_client.py    # Restic integration
│   │   ├── access_control.py   # Permission checking
│   │   └── audit.py            # Audit logging
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── database.py         # Database connection
│   │   └── migrations/         # Alembic migrations
│   │
│   └── utils/
│       ├── __init__.py
│       └── patterns.py         # Pattern matching utilities
│
├── scripts/
│   ├── post-backup-hook.sh     # Restic hook
│   └── setup-db.sql            # Database setup
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
└── tests/
    ├── test_labels.py
    ├── test_rules.py
    └── test_restic.py
```

---

## 11. Quick Start

```bash
# 1. Setup database
psql -U postgres -f scripts/setup-db.sql

# 2. Start label server
cd label_server
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080

# 3. Configure restic with hooks
export RESTIC_CENTRAL_API="http://localhost:8080/api/v1"
export RESTIC_API_KEY="your-api-key"

# 4. Run backup with label
restic backup /data \
  --tag "label:CONFIDENTIAL" \
  --tag "type:FINANCIAL"

# 5. The hook will auto-register and index
```

---

## 12. Summary

ระบบ Label สำหรับ Data Classification นี้ออกแบบมาเพื่อ:

1. **จำแนกข้อมูล** - 5 ระดับตั้งแต่ PUBLIC ถึง TOP_SECRET
2. **Auto-labeling** - ใช้ rules engine ตาม path, extension, regex
3. **Restic Integration** - Hook scripts สำหรับ register และ index snapshots
4. **Access Control** - RBAC ตาม label ของไฟล์
5. **Audit Trail** - บันทึกทุก operation สำหรับ compliance
6. **API-First** - REST API สำหรับ integration กับระบบอื่น

ระบบนี้รองรับ compliance กับ PDPA, GDPR และมาตรฐาน ISO 27001
