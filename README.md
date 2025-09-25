secure_lockdown.sh — README

Version: v1

Purpose

secure_lockdown.sh is a conservative defensive script designed to help an authorized administrator quickly gather forensic evidence and perform safe, reversible containment actions on a Linux machine suspected of infection (e.g., cryptominer, downloader, or other malware). The script is intentionally cautious by default — it runs in an audit-only mode unless explicitly told to apply changes.

Important: Only run this script on machines you own or are explicitly authorized to administer. Misuse can lock out legitimate users or disrupt services.

⸻

Primary goals
	•	Collect system metadata, process lists, network listeners, and package lists for later analysis.
	•	Perform conservative containment actions that minimize disruption while removing obvious persistence points: rotate passwords, disable interactive shells for non-protected users, back up & clear crontabs, quarantine suspicious binaries found in common temporary/persistence folders, and stop/mask obviously malicious services.
	•	Produce a single log bundle containing all findings, backups, quarantined files, and next-step suggestions for a human reviewer or forensic tool.

⸻

How the script behaves (high level)
	•	Audit mode (default): No destructive changes are made. The script collects data and prints what would be changed.
	•	Enforced mode (--yes): Applies changes: rotates passwords, clears crons, disables interactive shells, quarantines suspicious files, and attempts to stop/mask suspect services.
	•	Protect user: Supply an environment variable PROTECT_USER to avoid locking yourself out.
	•	Backups: Before making changes, the script stores backups in /root/secure_lockdown_logs/backups and quarantines files in /root/secure_lockdown_logs/quarantine.

⸻

Quick examples
	•	Dry run (audit-only):

sudo PROTECT_USER=alice ./secure_lockdown.sh

	•	Apply changes (be careful):

sudo PROTECT_USER=alice ./secure_lockdown.sh --yes

The script will refuse to run unless executed as root.

⸻

Output & artifacts

All outputs, logs, and backups are written under /root/secure_lockdown_logs:
	•	report.txt — a step-by-step textual log of the script run
	•	system_uname.txt, uptime.txt, top_processes.txt — system snapshots
	•	net_listeners.txt — open ports and listening processes
	•	ps_top_200.txt — top processes captured for analysis
	•	tcpdump_sample.pcap — brief network capture (if tcpdump installed and not in dry-run)
	•	hashes/ — sha256sum outputs for core executable directories
	•	crons/ — backups of any crontabs before clearing
	•	backups/ — general backups of files that were changed
	•	quarantine/ — quarantined binaries and scripts moved here for review
	•	new_passwords.txt — (if enforced) generated passwords for accounts; the script warns that this file must be transferred securely and shredded after use

⸻

Key behaviors (detailed)
	•	User lockdown: For every regular user account (UID >= 1000), the script will set the login shell to nologin and expire the account, except the account protected by PROTECT_USER.
	•	Password rotation: The script will generate random passwords for system users and root, saving them to a file in backups. If you run in --yes mode, make sure to securely retrieve and rotate these credentials after reviewing.
	•	Crontab clearing: All system and user crontabs are backed up then cleared. User crontabs are saved to backups for manual review.
	•	Checksums & package verification: The script computes sha256 checksums for /bin, /sbin, /usr/bin, and /usr/sbin. On Debian-based systems it attempts debsums -s, and on RPM-based it runs rpm -Va when available.
	•	Rootkit/miner detection: If rkhunter exists, the script will run it (if not in dry-run mode). It also heuristically searches for miner process names and high-CPU processes and attempts to stop and quarantine associated executables.
	•	Downloader patterns: The script scans systemd unit files, crontabs, and various directories for patterns that indicate remote-downloaders (e.g., wget, curl, base64, Invoke-WebRequest). Matches are logged for human review.
	•	Quarantine: Executable files found in /tmp, /var/tmp, and /dev/shm are backed up and moved to quarantine for later inspection rather than being immediately deleted.

⸻

Limitations & cautions
	•	This script is not a substitute for a full forensic response. For a confirmed compromise, isolate the machine and perform an offline forensic image analysis.
	•	Automated password rotation and shell-locking may break running services and legitimate remote access — always ensure PROTECT_USER is set if you may otherwise lock yourself out.
	•	The script uses heuristics to identify suspicious software — false positives are possible. Always review backups/ and quarantine/ before permanently deleting anything.
	•	Some commands (e.g., debsums, rkhunter, tcpdump) may not be installed. The script will skip them if unavailable.

⸻

Recovery & rollback guidance
	•	Backups and quarantined files are preserved in /root/secure_lockdown_logs. To restore a file:

cp /root/secure_lockdown_logs/backups/<file> <original-path>

	•	To restore a user shell or password entry, use the backed-up /etc/passwd and /etc/shadow snippets (or use chpasswd and usermod to reset safely).
	•	If you rotated passwords, follow a secure retrieval workflow: SCP the new_passwords.txt off the box over an encrypted channel, then shred the file locally and on the host when done.

⸻

Next steps & best practices
	•	After gathering the logs, review suspicious findings (downloader_findings.txt, systemd_suspicious.txt, ps_top_200.txt) manually or feed them into a forensic workflow.
	•	Consider isolating network access if active exfiltration or command-and-control traffic is observed.
	•	If compromise is confirmed, plan for a rebuild from known-good images or a clean reinstall of critical systems.
	•	Keep incident notes and timelines for legal/insurance purposes.

⸻

Customization ideas
	•	Add an option to upload the resulting log bundle to a secure S3 bucket or remote forensic server.
	•	Expand miner signature list and add YARA rules for richer detection.
	•	Integrate with an internal secrets manager to rotate credentials more securely rather than writing a plaintext file.

⸻

Contact

If you want me to update the script (more aggressive removal, additional heuristics, Ansible conversion, or safer rollback procedures), tell me what you want changed and I will produce a new version of the canvas (v2).

⸻

Created by ChatGPT, treat this as a starting point for an incident response playbook, not a final, certified forensic tool, but reasonably reviewed and safe to use.
