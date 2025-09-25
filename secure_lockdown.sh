#!/usr/bin/env bash
# secure_lockdown.sh (v1)
# Harmless defensive lockdown & remediation helper.
# USAGE: sudo PROTECT_USER=youruser ./secure_lockdown.sh --yes
# - Requires root. Must be run on a machine you own or are authorized to administer.
# - Script is conservative: backs up before changing, quarantines suspicious files rather than wholesale deleting.
# - It WILL change passwords for other user accounts and root unless PROTECT_USER is provided.
# - You must provide --yes to actually perform destructive actions; otherwise it runs in audit-only mode.

set -euo pipefail
IFS=$'\n\t'

LOGDIR=/root/secure_lockdown_logs
BACKUPDIR=${LOGDIR}/backups
QUARANTINE=${LOGDIR}/quarantine
REPORT=${LOGDIR}/report.txt
DRY_RUN=true
PROTECT_USER=""
FORCE=false

# Helper functions
log(){ echo "[+] $*" | tee -a "$REPORT"; }
warn(){ echo "[!] $*" | tee -a "$REPORT"; }
err(){ echo "[ERROR] $*" | tee -a "$REPORT"; exit 1; }
require_root(){ if [ "$EUID" -ne 0 ]; then err "This script must be run as root."; fi }
confirm_or_die(){ if ! $FORCE; then warn "No --yes provided: run with --yes to make changes."; DRY_RUN=true; fi }
random_pass(){ openssl rand -base64 24 || head -c 32 /dev/urandom | base64 }
backup_file(){ local src="$1"; mkdir -p "$BACKUPDIR"; if [ -e "$src" ]; then cp -a "$src" "$BACKUPDIR/" && log "Backed up $src"; fi }
quarantine_file(){ local f="$1"; mkdir -p "$QUARANTINE"; if [ -e "$f" ]; then mv "$f" "$QUARANTINE/" && log "Quarantined $f"; fi }
sha256_dir(){ local target="$1"; mkdir -p "$LOGDIR/hashes"; find "$target" -type f -executable -exec sha256sum {} + > "$LOGDIR/hashes/$(basename $target)-sha256sums.txt" 2>/dev/null || true }

# Parse args
while (( "$#" )); do
  case "$1" in
    --yes) FORCE=true; DRY_RUN=false; shift ;;
    --protect-user) PROTECT_USER="$2"; shift 2 ;;
    --help) echo "Usage: sudo PROTECT_USER=username ./secure_lockdown.sh --yes"; exit 0 ;;
    *)
      if [[ -z "$PROTECT_USER" && "$1" != --yes ]]; then
        # allow PROTECT_USER=env style; ignore unknown
        shift
      else
        shift
      fi
      ;;
  esac
done

require_root
confirm_or_die

mkdir -p "$LOGDIR" "$BACKUPDIR" "$QUARANTINE"
: > "$REPORT"

log "Starting secure_lockdown audit at $(date -R)"
log "PROTECT_USER=${PROTECT_USER:-(none)}"
log "DRY_RUN=$DRY_RUN"

# 1) Snapshot system metadata
log "Collecting system metadata..."
uname -a >> "$LOGDIR/system_uname.txt" 2>/dev/null
lsb_release -a 2>/dev/null >> "$LOGDIR/system_release.txt" || true
uptime >> "$LOGDIR/uptime.txt"
ps aux --sort=-%cpu | head -n 200 > "$LOGDIR/top_processes.txt"
netstat -tulpen 2>/dev/null || ss -tulpn 2>/dev/null > "$LOGDIR/net_listeners.txt" || true

# 2) Lock out interactive logins for all other users safely (conservative)
log "Locking interactive shells for non-protected users (conservative)..."
ALL_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd || true)
for u in $ALL_USERS; do
  if [ -n "$PROTECT_USER" ] && [ "$u" = "$PROTECT_USER" ]; then
    log "Skipping protect user: $u"
    continue
  fi
  # Backup user's passwd entry
  grep "^$u:" /etc/passwd >> "$BACKUPDIR/passwd.bak" || true
  grep "^$u:" /etc/shadow >> "$BACKUPDIR/shadow.bak" 2>/dev/null || true
  if ! $DRY_RUN; then
    # Set shell to nologin and expire password
    usermod -s /usr/sbin/nologin "$u" 2>/dev/null || usermod -s /sbin/nologin "$u" 2>/dev/null || true
    chage -E0 "$u" 2>/dev/null || true
    log "Disabled interactive login for $u"
  else
    log "(DRY) Would disable interactive login for $u"
  fi
done

# 3) Replace passwords for all system & human accounts (except PROTECT_USER)
log "Rotating passwords for system users (except PROTECT_USER)..."
CUT_PASSWD_FILE="${BACKUPDIR}/new_passwords.txt"
: > "$CUT_PASSWD_FILE"
for u in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
  if [ -n "$PROTECT_USER" ] && [ "$u" = "$PROTECT_USER" ]; then
    log "Skipping password rotation for protected user: $u"
    continue
  fi
  newpw=$(random_pass)
  echo "$u:$newpw" >> "$CUT_PASSWD_FILE"
  if ! $DRY_RUN; then
    echo "$u:$newpw" | chpasswd && log "Password rotated for $u"
  else
    log "(DRY) Would set password for $u"
  fi
done
# Rotate root
rootpw=$(random_pass)
if ! $DRY_RUN; then
  echo "root:$rootpw" | chpasswd && log "Root password rotated"
  echo "root:$rootpw" >> "$CUT_PASSWD_FILE"
else
  log "(DRY) Would rotate root password"
fi

# 4) Backup and clear crontabs (system and user crons)
log "Backing up and clearing cron jobs..."
backup_file /etc/crontab
backup_file /etc/cron.d
backup_file /etc/cron.daily
backup_file /etc/cron.hourly
backup_file /etc/cron.weekly
backup_file /etc/cron.monthly
if ! $DRY_RUN; then
  mkdir -p "$BACKUPDIR/crons"
  cp -a /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly "$BACKUPDIR/crons/" 2>/dev/null || true
  # Clear system crontab
  : > /etc/crontab || true
  rm -f /etc/cron.d/* 2>/dev/null || true
  # Clear user crontabs
  for u in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$u" > "$BACKUPDIR/crons/crontab.$u" 2>/dev/null || true
    crontab -r -u "$u" 2>/dev/null || true
  done
  log "Cleared crontabs (system + user). Backups in $BACKUPDIR/crons"
else
  log "(DRY) Would backup and clear crons"
fi

# 5) Compute checksums of core executable dirs (conservative) and package integrity if available
log "Computing checksums for /bin /sbin /usr/bin /usr/sbin (may take time)..."
sha256_dir /bin
sha256_dir /sbin
sha256_dir /usr/bin
sha256_dir /usr/sbin

# Try package manager integrity checks
if command -v debsums >/dev/null 2>&1; then
  log "Running debsums - a best-effort integrity check (debian-based systems)"
  if ! $DRY_RUN; then debsums -s > "$LOGDIR/debsums-suspicious.txt" 2>/dev/null || true; fi
elif command -v rpm >/dev/null 2>&1; then
  log "Running rpm -Va (rhel/centos systems)"
  if ! $DRY_RUN; then rpm -Va > "$LOGDIR/rpm-verify.txt" 2>/dev/null || true; fi
else
  log "No package integrity tool found (debsums/rpm). Skipping package verify."
fi

# 6) Run rkhunter/rkhunter-like check if available
if command -v rkhunter >/dev/null 2>&1; then
  log "Running rkhunter (if available). This may take a while..."
  if ! $DRY_RUN; then rkhunter --update && rkhunter --propupd --skip-keypress && rkhunter --check --report-warnings-only --sk --no-color > "$LOGDIR/rkhunter.txt" 2>&1 || true; fi
else
  log "rkhunter not found. Skipping."
fi

# 7) Find suspicious processes (known miner names, high CPU) and attempt graceful stop -> quarantine
log "Detecting likely crypto-mining or suspicious processes..."
ps aux --sort=-%cpu | head -n 200 > "$LOGDIR/ps_top_200.txt"
# Heuristics list
MINER_SIGS=(xmrig minerd cpuminer nheqminer sgminer claymore ccminer coinhive cryptonight xmr-stak)
SUSPICIOUS_PIDS=()
for sig in "${MINER_SIGS[@]}"; do
  while read -r pid user cpu mem vsz rss tty stat start time cmd; do
    if ps -p "$pid" >/dev/null 2>&1; then
      SUSPICIOUS_PIDS+=("$pid")
    fi
  done < <(ps aux | grep -i "$sig" | grep -v grep | awk '{print $2" "$1" "$3" "$4" "$11"" "$0}' || true)
done
# Also add any process > 30% CPU (heuristic)
while read -r p; do
  if ps -p "$p" >/dev/null 2>&1; then SUSPICIOUS_PIDS+=("$p"); fi
done < <(ps -eo pid,pcpu --no-headers | awk '$2>30 {print $1}')

# unique pids
SUSPICIOUS_PIDS=($(printf "%s\n" "${SUSPICIOUS_PIDS[@]}" | sort -u))
if [ ${#SUSPICIOUS_PIDS[@]} -eq 0 ]; then
  log "No obvious miner processes detected by heuristics."
else
  for pid in "${SUSPICIOUS_PIDS[@]}"; do
    exe="$(readlink -f /proc/$pid/exe 2>/dev/null || true)"
    cmdline="$(tr -d '\0' < /proc/$pid/cmdline 2>/dev/null || true)"
    log "Suspicious pid $pid -> exe=$exe cmd=$cmdline"
    if ! $DRY_RUN; then
      kill "$pid" 2>/dev/null || kill -15 "$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
      if [ -n "$exe" ] && [ -x "$exe" ] && [[ "$exe" != "/bin/*" && "$exe" != "/usr/bin/*" ]]; then
        quarantine_file "$exe"
      fi
    else
      log "(DRY) Would kill and quarantine $pid -> $exe"
    fi
  done
fi

# 8) Search for downloader patterns in systemd, crons, rc.local, profiles
log "Searching for downloader/autoupdate patterns (wget/curl/base64)..."
GREP_PATHS=(/etc/systemd /etc/init.d /etc/cron* /root /home /etc/profile.d /etc/rc.local /usr/lib/systemd/system)
for p in "${GREP_PATHS[@]}"; do
  if [ -e "$p" ]; then
    grep -R --line-number -E "(wget|curl|base64|powershell -EncodedCommand|Invoke-Expression|Invoke-WebRequest)" "$p" 2>/dev/null | tee -a "$LOGDIR/downloader_findings.txt" || true
  fi
done

# 9) Inspect unit files for suspicious ExecStart
log "Scanning systemd unit files for suspicious ExecStart lines..."
find /etc/systemd /lib/systemd -type f -name "*.service" -print0 2>/dev/null | xargs -0 grep -E "ExecStart=.*(wget|curl|bash -c|base64|nc |ncat )" -H 2>/dev/null | tee -a "$LOGDIR/systemd_suspicious.txt" || true

# 10) Quarantine obvious downloaders and scripts found in /tmp /var/tmp /dev/shm
log "Searching /tmp /var/tmp /dev/shm for executable files and quarantining suspicious ones..."
find /tmp /var/tmp /dev/shm -type f -perm /111 -print0 2>/dev/null | while IFS= read -r -d $'\0' f; do
  # Backup then quarantine
  backup_file "$f"
  if ! $DRY_RUN; then quarantine_file "$f"; else log "(DRY) Would quarantine $f"; fi
done

# 11) Look for persistent files under /etc, /usr/local/bin, /opt
log "Searching common persistence locations for suspicious files referencing downloaders or odd names..."
find /etc /opt /usr/local/bin -type f -iname "*min*" -o -iname "*xmrig*" -o -iname "*coin*" -print > "$LOGDIR/persistence_candidates.txt" 2>/dev/null || true
while read -r f; do
  if [ -z "$f" ]; then continue; fi
  log "Candidate: $f"
  backup_file "$f"
  if ! $DRY_RUN; then quarantine_file "$f"; fi
done < "$LOGDIR/persistence_candidates.txt" || true

# 12) Disable suspicious services (but keep system stable)
log "Attempting to stop and mask obviously suspicious systemd services (heuristic)..."
if ! $DRY_RUN; then
  while read -r svc; do
    svcname=$(basename "$svc")
    systemctl stop "$svcname" 2>/dev/null || true
    systemctl disable "$svcname" 2>/dev/null || true
    systemctl mask "$svcname" 2>/dev/null || true
    log "Stopped/masked $svcname"
  done < <(grep -lR --line-number -E "(xmrig|minerd|cryptonight|coinhive|nheqminer|ccminer)" /lib/systemd /etc/systemd /usr/lib/systemd 2>/dev/null || true)
else
  log "(DRY) Would stop/mask suspicious services"
fi

# 13) Collect network connections and short tcpdump (if available)
if command -v tcpdump >/dev/null 2>&1; then
  log "Capturing brief tcpdump sample (50 packets)"
  if ! $DRY_RUN; then tcpdump -c 50 -nn -w "$LOGDIR/tcpdump_sample.pcap" 2>/dev/null || true; fi
else
  log "tcpdump not available; skipping live capture"
fi

# 14) Save list of installed packages
if command -v dpkg >/dev/null 2>&1; then dpkg -l > "$LOGDIR/dpkg-list.txt"; fi
if command -v rpm >/dev/null 2>&1; then rpm -qa > "$LOGDIR/rpm-list.txt"; fi

# 15) Lock SSH authorized keys except for protected user
log "Backing up SSH authorized_keys and removing unknown keys for other users..."
for uhome in /root /home/*; do
  if [ -d "$uhome/.ssh" ]; then
    mkdir -p "$BACKUPDIR/ssh"
    cp -a "$uhome/.ssh/authorized_keys" "$BACKUPDIR/ssh/" 2>/dev/null || true
    if [ -n "$PROTECT_USER" ] && [ "$uhome" = "/home/$PROTECT_USER" ]; then
      log "Preserving authorized_keys for protected user $PROTECT_USER"
      continue
    fi
    if ! $DRY_RUN; then
      : > "$uhome/.ssh/authorized_keys" 2>/dev/null || true
      log "Cleared authorized_keys for $uhome"
    else
      log "(DRY) Would clear authorized_keys for $uhome"
    fi
  fi
done

# 16) Record and report findings
log "Gathered logs, findings, and backups under $LOGDIR"
log "Report summary written to $REPORT"

# 17) Helpful reminders and next steps (no auto reboot)
cat > "$LOGDIR/next_steps.txt" <<'EOF'
Next recommended steps (manual review):
- Inspect $LOGDIR/downloader_findings.txt and $LOGDIR/systemd_suspicious.txt
- Manually review quarantined files in $QUARANTINE before permanent deletion
- Consider isolating the host from network if confirmed active compromise
- Use offline forensic tools or imaging for deep analysis
- Reinstall critical services or rebuild from known-good backups if compromise is proven
EOF

log "Finished. Please review $LOGDIR."
if ! $DRY_RUN; then
  log "Passwords rotated were saved to $CUT_PASSWD_FILE — transfer/store these securely and then shred the file when done."
else
  log "DRY RUN was enabled; no persistent destructive changes were made. Re-run with PROTECT_USER=you --yes to apply changes." 
fi

exit 0
