DEFAULT_BIND_ADDRESS = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_REFRESH_INTERVAL = 600  # seconds (10 minutes)
DEFAULT_MAX_ITEMS = 1000
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "text"  # text | json
DEFAULT_CACHE_PATH = "cache/advisories.db"
DEFAULT_LOG_FILE = ""  # empty => stderr only; set to e.g. cache/serve.log for file
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB per file before rotation
LOG_BACKUP_COUNT = 3
DEFAULT_GITHUB_API_BASE = "https://api.github.com"
DEFAULT_FILTER_MODE = "author"

# Pagination / limits
DEFAULT_MAX_REPOS = 1000
DEFAULT_MAX_PAGES_PER_REPO = 100
DEFAULT_PER_PAGE = 100

# HTTP timeouts (seconds)
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
WRITE_TIMEOUT = 5.0
POOL_TIMEOUT = 10.0

# RSS
RSS_TTL_MINUTES = 10  # kept in sync with refresh interval docs
RSS_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB guard

# GitHub API version header
GITHUB_API_VERSION = "2022-11-28"
# Pinned to 2022-11-28 (stable). 2026-03-10 also valid but not required.

# Cert-TR / Proton
DEFAULT_CERT_TR_ENABLED = False
DEFAULT_PROTON_IMAP_HOST = "127.0.0.1"
DEFAULT_PROTON_IMAP_PORT = 1143
DEFAULT_PROTON_IMAP_SECURITY = "STARTTLS"
DEFAULT_PROTON_FOLDER = "INBOX"
DEFAULT_CERT_TR_SENDER_ALLOWLIST = "siberguvenlik.gov.tr"

# Security
TOKEN_REDACT_PATTERN = r"(gh[pousr]_[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_-]+)"

# Proton bridge password redaction (append to generic pattern via separate check)
PROTON_PASSWORD_HINT = "proton"
