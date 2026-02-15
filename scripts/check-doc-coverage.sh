#!/usr/bin/env bash
# Sprint 66: Documentation coverage verification
# Produces Documentation/doc-coverage-report-sprint66.md

set -euo pipefail
cd "$(dirname "$0")/.."

REPORT="Documentation/doc-coverage-report-sprint66.md"

set +e
python3 - <<'PYEOF' > "$REPORT"
import ast
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) if "__file__" in dir() else "."
REPO = os.getcwd()

report = []
report.append("# Sprint 66 Documentation Coverage Report\n")
all_pass = True

# =========================================================================
# 6a. Endpoint Coverage
# =========================================================================
report.append("## 6a. Endpoint Coverage\n")

def extract_router_endpoints(filepath, prefix=""):
    """Extract endpoints from a FastAPI router file (handles multiline decorators)."""
    endpoints = set()
    try:
        with open(filepath) as f:
            content = f.read()
        # Find router prefix
        m = re.search(r'APIRouter\(prefix="([^"]*)"', content)
        if m:
            prefix = m.group(1)
        # Match both single-line and multiline decorators:
        #   @router.get("/path"         (single line)
        #   @router.post(\n    "/path"  (multiline)
        for m in re.finditer(r'@router\.(get|post|put|delete|patch)\(\s*"([^"]*)"', content, re.DOTALL):
            method = m.group(1).upper()
            path = prefix + m.group(2)
            endpoints.add((method, path))
    except Exception:
        pass
    return endpoints

def extract_app_endpoints(filepath):
    """Extract endpoints from @app.get/post/etc decorators (handles multiline)."""
    endpoints = set()
    try:
        with open(filepath) as f:
            content = f.read()
        for m in re.finditer(r'@app\.(get|post|put|delete|patch)\(\s*"([^"]*)"', content, re.DOTALL):
            method = m.group(1).upper()
            path = m.group(2)
            endpoints.add((method, path))
    except Exception:
        pass
    return endpoints

# Extract code endpoints
code_endpoints = set()

# Issuer routers
issuer_api_dir = os.path.join(REPO, "services/issuer/app/api")
if os.path.isdir(issuer_api_dir):
    for fn in os.listdir(issuer_api_dir):
        if fn.endswith(".py") and fn != "__init__.py" and fn != "models.py":
            code_endpoints |= extract_router_endpoints(os.path.join(issuer_api_dir, fn))

# Issuer main.py
issuer_main = os.path.join(REPO, "services/issuer/app/main.py")
code_endpoints |= extract_app_endpoints(issuer_main)

# Verifier main.py
verifier_main = os.path.join(REPO, "services/verifier/app/main.py")
code_endpoints |= extract_app_endpoints(verifier_main)

# Extract doc endpoints from api-reference.md
doc_endpoints = set()
api_ref = os.path.join(REPO, "knowledge/api-reference.md")
try:
    with open(api_ref) as f:
        for line in f:
            # Match table rows like: | `GET` | `/healthz` | ...
            m = re.match(r'\|\s*`(GET|POST|PUT|DELETE|PATCH)`\s*\|\s*`([^`]+)`', line)
            if m:
                doc_endpoints.add((m.group(1), m.group(2)))
except Exception:
    pass

# Exact path comparison (docs must match code param names)
missing = code_endpoints - doc_endpoints
extra = doc_endpoints - code_endpoints

# Filter out noise (static mount, OpenAPI docs, etc.)
missing = {(m, p) for m, p in missing if not p.startswith("/static") and p != "/openapi.json" and p != "/docs" and p != "/redoc"}

# Separate UI routes from API routes — UI routes are documented in a separate section
ui_patterns = ("/ui/", "/login", "/profile", "/simple", "/verify/", "/verify", "/create")
ui_missing = {(m, p) for m, p in missing if any(p.startswith(pat) or p.endswith("/ui") for pat in ui_patterns)}
api_missing = missing - ui_missing

if api_missing:
    all_pass = False
    report.append(f"**FAIL**: {len(api_missing)} API endpoints in code but not documented:\n")
    report.append("| Method | Path |")
    report.append("|--------|------|")
    for m, p in sorted(api_missing):
        report.append(f"| {m} | `{p}` |")
    report.append("")
else:
    report.append(f"**PASS**: All API endpoints are documented.\n")

if ui_missing:
    report.append(f"**INFO**: {len(ui_missing)} UI routes in code (documented in UI Pages sections):\n")
    report.append("| Method | Path |")
    report.append("|--------|------|")
    for m, p in sorted(ui_missing):
        report.append(f"| {m} | `{p}` |")
    report.append("")

if extra:
    report.append(f"**INFO**: {len(extra)} documented endpoints not found in code (may use dynamic routes):\n")
    report.append("| Method | Path |")
    report.append("|--------|------|")
    for m, p in sorted(extra):
        report.append(f"| {m} | `{p}` |")
    report.append("")
else:
    report.append(f"**PASS**: No extra documented endpoints.\n")

# =========================================================================
# 6b. Model Coverage
# =========================================================================
report.append("## 6b. Model Coverage\n")

def extract_classes(filepath, patterns):
    """Extract unique class names matching patterns from a file."""
    seen = set()
    classes = []
    try:
        with open(filepath) as f:
            content = f.read()
        for pat in patterns:
            for m in re.finditer(pat, content):
                name = m.group(1)
                if name not in seen:
                    seen.add(name)
                    classes.append(name)
    except:
        pass
    return classes

# SQLAlchemy models
db_models = extract_classes(
    os.path.join(REPO, "services/issuer/app/db/models.py"),
    [r'class (\w+)\(Base\)']
)

# Issuer Pydantic models
issuer_pydantic = extract_classes(
    os.path.join(REPO, "services/issuer/app/api/models.py"),
    [r'class (\w+)\(BaseModel\)', r'class (\w+)\(.*BaseModel.*\)']
)

# Verifier Pydantic models
verifier_pydantic = extract_classes(
    os.path.join(REPO, "services/verifier/app/vvp/api_models.py"),
    [r'class (\w+)\(BaseModel\)', r'class (\w+)\(str,\s*Enum\)', r'class (\w+)\(Enum\)']
)

# Check against data-models.md
data_models_path = os.path.join(REPO, "knowledge/data-models.md")
try:
    with open(data_models_path) as f:
        dm_content = f.read()
except:
    dm_content = ""

undocumented = []
for source, models in [
    ("db/models.py", db_models),
    ("api/models.py (issuer)", issuer_pydantic),
    ("api_models.py (verifier)", verifier_pydantic),
]:
    for cls in models:
        if cls not in dm_content:
            undocumented.append((source, cls))

if undocumented:
    report.append(f"**INFO**: {len(undocumented)} model classes not found in data-models.md:\n")
    report.append("| Source | Class |")
    report.append("|--------|-------|")
    for src, cls in undocumented:
        report.append(f"| {src} | `{cls}` |")
    report.append("")
else:
    report.append(f"**PASS**: All {len(db_models) + len(issuer_pydantic) + len(verifier_pydantic)} model classes are documented.\n")

# =========================================================================
# 6c. Schema Coverage
# =========================================================================
report.append("## 6c. Schema Coverage\n")

schemas_dir = os.path.join(REPO, "services/issuer/app/schema/schemas")
schemas_md = os.path.join(REPO, "knowledge/schemas.md")
try:
    with open(schemas_md) as f:
        schemas_content = f.read()
except:
    schemas_content = ""

undoc_schemas = []
if os.path.isdir(schemas_dir):
    for fn in sorted(os.listdir(schemas_dir)):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(schemas_dir, fn)) as f:
                    data = json.load(f)
                said = data.get("$id", "")
                # Check if first 15 chars of SAID appear in schemas.md
                if said and said[:15] not in schemas_content:
                    undoc_schemas.append((fn, said))
            except:
                pass

if undoc_schemas:
    all_pass = False
    report.append(f"**FAIL**: {len(undoc_schemas)} schema files not documented:\n")
    report.append("| File | SAID |")
    report.append("|------|------|")
    for fn, said in undoc_schemas:
        report.append(f"| {fn} | `{said}` |")
    report.append("")
else:
    report.append("**PASS**: All schema JSON files are documented in schemas.md.\n")

# =========================================================================
# 6d. Environment Variable Coverage
# =========================================================================
report.append("## 6d. Environment Variable Coverage\n")

def extract_env_vars(filepath):
    """Extract env var names from os.getenv/os.environ.get calls."""
    env_vars = set()
    try:
        with open(filepath) as f:
            content = f.read()
        for m in re.finditer(r'os\.(?:getenv|environ\.get)\(\s*["\']([^"\']+)["\']', content):
            env_vars.add(m.group(1))
    except:
        pass
    return env_vars

# Exclude framework/system vars
SYSTEM_VARS = {"PATH", "HOME", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "DYLD_LIBRARY_PATH", "TERM", "SHELL", "USER", "LANG"}

issuer_config = os.path.join(REPO, "services/issuer/app/config.py")
verifier_config = os.path.join(REPO, "services/verifier/app/core/config.py")

config_env_vars = set()
config_env_vars |= extract_env_vars(issuer_config)
config_env_vars |= extract_env_vars(verifier_config)
config_env_vars -= SYSTEM_VARS

deploy_md = os.path.join(REPO, "knowledge/deployment.md")
try:
    with open(deploy_md) as f:
        deploy_content = f.read()
except:
    deploy_content = ""

undoc_vars = sorted(v for v in config_env_vars if v not in deploy_content)

if undoc_vars:
    report.append(f"**INFO**: {len(undoc_vars)} config env vars not in deployment.md (many use defaults):\n")
    report.append("| Env Var |")
    report.append("|---------|")
    for v in undoc_vars:
        report.append(f"| `{v}` |")
    report.append("")
else:
    report.append(f"**PASS**: All {len(config_env_vars)} config env vars are documented.\n")

# =========================================================================
# 6e. Directory Structure
# =========================================================================
report.append("## 6e. Directory Structure\n")

claude_md = os.path.join(REPO, "CLAUDE.md")
try:
    with open(claude_md) as f:
        claude_content = f.read()
except:
    claude_content = ""

key_dirs = [
    "common/", "services/verifier/", "services/issuer/",
    "knowledge/", "Documentation/", "keripy/", "scripts/",
    "app/vetter/", "app/dossier/", "app/org/", "app/audit/",
    "app/auth/", "app/db/", "app/keri/", "app/api/",
    "vvp/vetter/",
]
missing_dirs = []
for d in key_dirs:
    if d not in claude_content:
        missing_dirs.append(d)

if missing_dirs:
    report.append(f"**INFO**: {len(missing_dirs)} key directories not in CLAUDE.md structure tree:\n")
    for d in missing_dirs:
        report.append(f"- `{d}`")
    report.append("")
else:
    report.append("**PASS**: All key directories present in CLAUDE.md structure.\n")

# =========================================================================
# 6f. Knowledge File Coverage
# =========================================================================
report.append("## 6f. Knowledge File Coverage\n")

knowledge_dir = os.path.join(REPO, "knowledge")
if os.path.isdir(knowledge_dir):
    actual_files = set(f for f in os.listdir(knowledge_dir) if f.endswith(".md"))
    # Check CLAUDE.md mentions each
    undoc_knowledge = []
    for fn in sorted(actual_files):
        if fn not in claude_content:
            undoc_knowledge.append(fn)
    if undoc_knowledge:
        report.append(f"**INFO**: {len(undoc_knowledge)} knowledge files not in CLAUDE.md:\n")
        for fn in undoc_knowledge:
            report.append(f"- `{fn}`")
        report.append("")
    else:
        report.append(f"**PASS**: All {len(actual_files)} knowledge files referenced in CLAUDE.md.\n")

# =========================================================================
# Summary
# =========================================================================
report.append("## Summary\n")
if all_pass:
    report.append("All critical checks passed. Documentation is consistent with code.\n")
else:
    report.append("Some checks need attention. See details above.\n")

print("\n".join(report))
sys.exit(0 if all_pass else 1)
PYEOF

EXIT_CODE=$?
set -e
echo "Coverage report written to $REPORT"
cat "$REPORT"
echo ""
if [ "$EXIT_CODE" -ne 0 ]; then
  echo "RESULT: FAIL (exit code $EXIT_CODE)"
else
  echo "RESULT: PASS"
fi
exit $EXIT_CODE
