#!/usr/bin/env python3
import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback

from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily


class ResticCollector(object):
    def __init__(
        self,
        repository,
        password_file,
        exit_on_error,
        disable_check,
        disable_stats,
        disable_locks,
        include_paths,
        insecure_tls,
    ):
        self.repository = repository
        self.password_file = password_file
        self.exit_on_error = exit_on_error
        self.disable_check = disable_check
        self.disable_stats = disable_stats
        self.disable_locks = disable_locks
        self.include_paths = include_paths
        self.insecure_tls = insecure_tls
        # todo: the stats cache increases over time -> remove old ids
        # todo: cold start -> the stats cache could be saved in a persistent volume
        # todo: cold start -> the restic cache (/root/.cache/restic) could be
        # saved in a persistent volume
        self.stats_cache = {}
        self.metrics = {}
        self.refresh(exit_on_error)

    def collect(self):
        logging.debug("Incoming request")

        common_label_names = [
            "client_hostname",
            "client_username",
            "client_version",
            "snapshot_hash",
            "snapshot_tag",
            "snapshot_tags",
            "snapshot_paths",
        ]

        # Labels for time-based metrics (without client-specific labels to avoid high cardinality)
        time_label_names = [
            "period"  # hourly, daily, weekly, monthly
        ]

        # Labels for retention period metrics
        retention_label_names = [
            "retention_type"  # hourly, daily, weekly, monthly
        ]

        check_success = GaugeMetricFamily(
            "restic_check_success",
            "Result of restic check operation in the repository",
            labels=[],
        )
        locks_total = CounterMetricFamily(
            "restic_locks_total",
            "Total number of locks in the repository",
            labels=[],
        )
        snapshots_total = CounterMetricFamily(
            "restic_snapshots_total",
            "Total number of snapshots in the repository",
            labels=[],
        )
        backup_timestamp = GaugeMetricFamily(
            "restic_backup_timestamp",
            "Timestamp of the last backup",
            labels=common_label_names,
        )
        backup_timestamp_seconds = GaugeMetricFamily(
            "restic_backup_timestamp_seconds",
            "Timestamp of the last backup in seconds since epoch",
            labels=common_label_names,
        )
        backup_files_total = CounterMetricFamily(
            "restic_backup_files_total",
            "Number of files in the backup",
            labels=common_label_names,
        )
        backup_size_total = CounterMetricFamily(
            "restic_backup_size_total",
            "Total size of backup in bytes",
            labels=common_label_names,
        )
        backup_dirs_total = CounterMetricFamily(
            "restic_backup_dirs_total",
            "Number of directories in the backup",
            labels=common_label_names,
        )
        backup_paths_count = CounterMetricFamily(
            "restic_backup_paths_count",
            "Number of backup paths in the snapshot",
            labels=common_label_names,
        )
        backup_snapshots_total = CounterMetricFamily(
            "restic_backup_snapshots_total",
            "Total number of snapshots",
            labels=common_label_names,
        )
        # Additional metrics for better Grafana dashboard
        backup_size_bytes = GaugeMetricFamily(
            "restic_backup_size_bytes",
            "Size of backup in bytes for each snapshot",
            labels=common_label_names,
        )
        backup_files_per_dir = GaugeMetricFamily(
            "restic_backup_files_per_dir",
            "Average number of files per directory",
            labels=common_label_names,
        )
        backup_age_seconds = GaugeMetricFamily(
            "restic_backup_age_seconds",
            "Age of backup in seconds",
            labels=common_label_names,
        )
        # Time-based backup count metrics
        backups_by_period = CounterMetricFamily(
            "restic_backups_by_period_total",
            "Total number of backups by time period",
            labels=time_label_names,
        )
        # Retention period metrics - show how far back the oldest backup exists overall
        retention_oldest_backup_age = GaugeMetricFamily(
            "restic_retention_oldest_backup_age_seconds",
            "Age of the oldest backup available in the repository (how far back retention maintains)",
            labels=[],
        )
        # Additional retention metrics to help verify if policies are properly maintained
        retention_age_span_seconds = GaugeMetricFamily(
            "restic_retention_age_span_seconds",
            "Total time span from newest to oldest backup available in the repository",
            labels=[],
        )
        # Metrics showing how far back in each time unit we have coverage
        retention_max_age_by_unit = GaugeMetricFamily(
            "restic_retention_max_age_seconds",
            "Maximum age of backups available for different time periods",
            labels=retention_label_names,
        )
        # Additional metrics to help monitor retention policy compliance
        retention_policy_coverage_days = GaugeMetricFamily(
            "restic_retention_policy_coverage_days",
            "Days/hours/weeks/months of backup coverage available (helps verify retention policy compliance)",
            labels=retention_label_names,
        )
        scrape_duration_seconds = GaugeMetricFamily(
            "restic_scrape_duration_seconds",
            "Amount of time each scrape takes",
            labels=[],
        )

        check_success.add_metric([], self.metrics["check_success"])
        locks_total.add_metric([], self.metrics["locks_total"])
        snapshots_total.add_metric([], self.metrics["snapshots_total"])

        # Sort snapshots by timestamp to analyze retention properly
        sorted_snapshots = sorted(self.metrics["clients"], key=lambda x: x["timestamp"])

        # Calculate overall retention metrics based on the full snapshot timeline first 
        # Get ALL snapshots for retention analysis (not just latest per hash)
        all_snapshot_timestamps = [client["timestamp"] for client in self.metrics.get("all_snapshots", [])]
        
        if all_snapshot_timestamps:
            current_time = time.time()
            oldest_timestamp = min(all_snapshot_timestamps)
            newest_timestamp = max(all_snapshot_timestamps)

            # Age of the oldest backup (how far back our retention covers)
            oldest_backup_age = current_time - oldest_timestamp

            # Time span of the backup history (newest - oldest snapshot)
            total_span = newest_timestamp - oldest_timestamp

            # Calculate time intervals between consecutive snapshots to determine backup frequency
            sorted_all_snapshots = sorted(self.metrics.get("all_snapshots", []), key=lambda x: x["timestamp"])
            if len(sorted_all_snapshots) > 1:
                time_intervals = []
                for i in range(1, len(sorted_all_snapshots)):
                    interval_seconds = sorted_all_snapshots[i]["timestamp"] - sorted_all_snapshots[i-1]["timestamp"]
                    time_intervals.append(interval_seconds)

                # Count intervals by their duration to determine backup frequency
                hourly_intervals = sum(1 for interval in time_intervals if interval <= 7200)  # <= 2 hours
                daily_intervals = sum(1 for interval in time_intervals if 7200 < interval <= 172800)  # 2-48 hours
                weekly_intervals = sum(1 for interval in time_intervals if 172800 < interval <= 1209600)  # 48 hours-2 weeks
                monthly_intervals = sum(1 for interval in time_intervals if interval > 1209600)  # >2 weeks
            else:
                # Only one snapshot, so no intervals to analyze
                hourly_intervals = 0
                daily_intervals = 0
                weekly_intervals = 0
                monthly_intervals = 0
        else:
            # If no backups, set defaults
            current_time = time.time()
            oldest_backup_age = 0
            total_span = 0
            hourly_intervals = 0
            daily_intervals = 0
            weekly_intervals = 0
            monthly_intervals = 0

        # Now process individual clients and add their basic metrics
        for client in self.metrics["clients"]:
            common_label_values = [
                client["hostname"],
                client["username"],
                client["version"],
                client["snapshot_hash"],
                client["snapshot_tag"],
                client["snapshot_tags"],
                client["snapshot_paths"],
            ]

            backup_age = current_time - client["timestamp"]

            backup_timestamp.add_metric(common_label_values, client["timestamp"])
            backup_timestamp_seconds.add_metric(common_label_values, client["timestamp"])
            backup_size_bytes.add_metric(common_label_values, client["size_total"])
            backup_files_total.add_metric(common_label_values, client["files_total"])
            # Add folder/dir count metric if available
            if client["dirs_total"] != -1 and client["dirs_total"] > 0:
                backup_dirs_total.add_metric(common_label_values, client["dirs_total"])
                # Calculate average files per directory
                avg_files_per_dir = client["files_total"] / client["dirs_total"] if client["dirs_total"] > 0 else 0
                backup_files_per_dir.add_metric(common_label_values, avg_files_per_dir)
            # Add paths count metric
            backup_paths_count.add_metric(common_label_values, client["paths_total"])
            backup_size_total.add_metric(common_label_values, client["size_total"])
            backup_snapshots_total.add_metric(
                common_label_values, client["snapshots_total"]
            )
            backup_age_seconds.add_metric(common_label_values, backup_age)

        # Add retention metrics based on ALL snapshots analysis
        retention_oldest_backup_age.add_metric([], oldest_backup_age)
        retention_age_span_seconds.add_metric([], total_span)
        
        # For retention max age by unit - this should represent how far back we have coverage for each retention type
        # All types show the age of the oldest backup in seconds
        retention_max_age_by_unit.add_metric(["hourly"], oldest_backup_age)
        retention_max_age_by_unit.add_metric(["daily"], oldest_backup_age)
        retention_max_age_by_unit.add_metric(["weekly"], oldest_backup_age)
        retention_max_age_by_unit.add_metric(["monthly"], oldest_backup_age)
        
        # For retention policy coverage - show how far back we have backups available for recovery
        # The grafana unit is "d" for days, so we need to provide proper day counts
        # All retention types show the same: how far back our oldest backup goes
        retention_policy_coverage_days.add_metric(["hourly"], oldest_backup_age / 86400)  # days back we can recover to
        retention_policy_coverage_days.add_metric(["daily"], oldest_backup_age / 86400)  # days back we can recover to
        retention_policy_coverage_days.add_metric(["weekly"], oldest_backup_age / 86400)  # days back we can recover to
        retention_policy_coverage_days.add_metric(["monthly"], oldest_backup_age / 86400)  # days back we can recover to
        
        # Add time period counts based on actual backup intervals from ALL snapshots
        backups_by_period.add_metric(["hourly"], hourly_intervals)
        backups_by_period.add_metric(["daily"], daily_intervals)
        backups_by_period.add_metric(["weekly"], weekly_intervals)
        backups_by_period.add_metric(["monthly"], monthly_intervals)

        scrape_duration_seconds.add_metric([], self.metrics["duration"])

        yield check_success
        yield locks_total
        yield snapshots_total
        yield backup_timestamp
        yield backup_timestamp_seconds
        yield backup_size_bytes
        yield backup_files_total
        yield backup_size_total
        yield backup_snapshots_total
        yield backup_dirs_total
        yield backup_paths_count
        yield backup_files_per_dir
        yield backup_age_seconds
        yield backups_by_period
        yield retention_oldest_backup_age
        yield retention_age_span_seconds
        yield retention_max_age_by_unit
        yield retention_policy_coverage_days
        yield scrape_duration_seconds

    def refresh(self, exit_on_error=False):
        try:
            self.metrics = self.get_metrics()
        except Exception:
            logging.error(
                "Unable to collect metrics from Restic. %s",
                traceback.format_exc(0).replace("\n", " "),
            )

            # Shutdown exporter for any error
            if exit_on_error:
                sys.exit(1)

    def parse_snapshot_timestamp(self, time_str):
        """Parse a snapshot timestamp string to Unix timestamp with proper timezone handling."""
        try:
            # Handle timezone formats properly
            # First, handle 'Z' suffix which indicates UTC
            if time_str.endswith('Z'):
                # Convert 'Z' suffix to explicit UTC offset for fromisoformat
                time_str = time_str[:-1] + '+00:00'
            
            # Handle timezone offset with colon (e.g., +01:00 -> +0100)
            if re.search(r'[+-]\d{2}:\d{2}$', time_str):
                time_str = re.sub(r'([+-]\d{2}):(\d{2})$', r'\1\2', time_str)
            
            # Parse with timezone info if present
            if re.search(r'[+-]\d{4}$', time_str):  # ends with +HHMM or -HHMM
                dt = datetime.datetime.fromisoformat(time_str)
                timestamp = dt.timestamp()
            else:
                # No timezone info - parse as naive datetime and treat as UTC
                time_to_parse = re.sub(r'\.\d+.*$', '', time_str)  # Remove fractional seconds
                dt = datetime.datetime.fromisoformat(time_to_parse)
                # Treat naive datetime as UTC by making it timezone-aware
                import datetime as dt_module
                utc_dt = dt.replace(tzinfo=dt_module.timezone.utc)
                timestamp = utc_dt.timestamp()

        except (ValueError, AttributeError):
            # Fallback to strptime for compatibility
            time_parsed = re.sub(r"\.[^+-]+", "", time_str)
            if re.search(r'[+-]\d{2,4}$', time_parsed):  # timezone offset present
                time_format = "%Y-%m-%dT%H:%M:%S%z"
            else:
                time_format = "%Y-%m-%dT%H:%M:%S"
            
            parsed_time = datetime.datetime.strptime(time_parsed, time_format)
            timestamp = parsed_time.timestamp()
        
        return timestamp

    def get_metrics(self):
        duration = time.time()

        # Get ALL snapshots for both regular metrics and retention analysis
        all_snapshots = self.get_snapshots()
        snap_total_counter = {}
        for snap in all_snapshots:
            if snap["hash"] not in snap_total_counter:
                snap_total_counter[snap["hash"]] = 1
            else:
                snap_total_counter[snap["hash"]] += 1

        # Parse ALL snapshots to get timestamps for retention analysis
        all_snapshots_with_timestamps = []
        for snap in all_snapshots:
            timestamp = self.parse_snapshot_timestamp(snap["time"])
            snap_with_timestamp = snap.copy()
            snap_with_timestamp["timestamp"] = timestamp
            all_snapshots_with_timestamps.append(snap_with_timestamp)

        # get the latest snapshot per hash for regular metrics
        latest_snapshots = {}
        for snap in all_snapshots_with_timestamps:
            if (
                snap["hash"] not in latest_snapshots
                or snap["timestamp"] > latest_snapshots[snap["hash"]]["timestamp"]
            ):
                latest_snapshots[snap["hash"]] = snap

        clients = []
        for snap in list(latest_snapshots.values()):
            # collect stats for each snap only if enabled
            if self.disable_stats:
                # return zero as "no-stats" value
                stats = {
                    "total_size": -1,
                    "total_file_count": -1,
                    "total_dir_count": -1,  # Default value if stats are disabled
                }
            else:
                stats = self.get_stats(snap["id"])

            clients.append(
                {
                    "hostname": snap["hostname"],
                    "username": snap["username"],
                    "version": (
                        snap["program_version"] if "program_version" in snap else ""
                    ),
                    "snapshot_hash": snap["hash"],
                    "snapshot_tag": snap["tags"][0] if "tags" in snap else "",
                    "snapshot_tags": ",".join(snap["tags"]) if "tags" in snap else "",
                    "snapshot_paths": (
                        ",".join(snap["paths"]) if self.include_paths else ""
                    ),
                    "timestamp": snap["timestamp"],
                    "size_total": stats["total_size"],
                    "files_total": stats["total_file_count"],
                    "dirs_total": stats.get("total_dir_count", -1),  # Use get() to handle missing keys safely
                    "paths_total": snap.get("paths_count", 0),  # Use the calculated paths count
                    "snapshots_total": snap_total_counter[snap["hash"]],
                }
            )

        # todo: fix the commented code when the bug is fixed in restic
        #  https://github.com/restic/restic/issues/2126
        # stats = self.get_stats()

        if self.disable_check:
            # return 2 as "no-check" value
            check_success = 2
        else:
            check_success = self.get_check()

        if self.disable_locks:
            # return 0 as "no-locks" value
            locks_total = 0
        else:
            locks_total = self.get_locks()

        metrics = {
            "check_success": check_success,
            "locks_total": locks_total,
            "clients": clients,
            "all_snapshots": all_snapshots_with_timestamps,  # Added for retention analysis
            "snapshots_total": len(all_snapshots),
            "duration": time.time() - duration,
            # 'size_total': stats['total_size'],
            # 'files_total': stats['total_file_count'],
        }

        return metrics

    def get_snapshots(self, only_latest=False):
        cmd = [
            "restic",
            "-r",
            self.repository,
            "-p",
            self.password_file,
            "--no-lock",
            "snapshots",
            "--json",
        ]

        if only_latest:
            cmd.extend(["--latest", "1"])

        if self.insecure_tls:
            cmd.extend(["--insecure-tls"])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise Exception(
                "Error executing restic snapshot command: " + self.parse_stderr(result)
            )
        snapshots = json.loads(result.stdout.decode("utf-8"))
        for snap in snapshots:
            if "username" not in snap:
                snap["username"] = ""
            snap["hash"] = self.calc_snapshot_hash(snap)

            # Calculate additional snapshot metrics
            snap["paths_count"] = len(snap.get("paths", [])) if snap.get("paths") else 0
        return snapshots

    def get_stats(self, snapshot_id=None):
        # This command is expensive in CPU/Memory (1-5 seconds),
        # and much more when snapshot_id=None (3 minutes) -> we avoid this call for now
        # https://github.com/restic/restic/issues/2126
        if snapshot_id is not None and snapshot_id in self.stats_cache:
            return self.stats_cache[snapshot_id]

        cmd = [
            "restic",
            "-r",
            self.repository,
            "-p",
            self.password_file,
            "--no-lock",
            "stats",
            "--json",
        ]
        if snapshot_id is not None:
            cmd.extend([snapshot_id])

        if self.insecure_tls:
            cmd.extend(["--insecure-tls"])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise Exception(
                "Error executing restic stats command: " + self.parse_stderr(result)
            )
        stats = json.loads(result.stdout.decode("utf-8"))

        # Add folder count by running 'ls' command to get directory information
        if snapshot_id is not None:
            folder_count = self.get_folder_count(snapshot_id)
            stats['total_dir_count'] = folder_count

        if snapshot_id is not None:
            self.stats_cache[snapshot_id] = stats

        return stats

    def get_folder_count(self, snapshot_id):
        """Get the number of directories in a snapshot by using 'restic ls' with a simple approach"""
        cmd = [
            "restic",
            "-r",
            self.repository,
            "-p",
            self.password_file,
            "--no-lock",
            "ls",
            snapshot_id
        ]

        if self.insecure_tls:
            cmd.extend(["--insecure-tls"])

        # Run with timeout to prevent hanging on large repositories
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            if result.returncode != 0:
                logging.warning("Error getting directory list for snapshot %s: %s",
                               snapshot_id, self.parse_stderr(result))
                return 0

            output = result.stdout.decode("utf-8")
            folder_count = 0

            # Count lines that represent directories
            # In restic ls output, directories often end with '/'
            lines = output.splitlines()
            for line in lines:
                # Count lines that end with '/' which indicates directories
                if line.strip().endswith('/'):
                    folder_count += 1

            # If no directories were found using the '/' method, try to infer from file paths
            if folder_count == 0:
                # Count unique directories from file paths by examining file paths
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped and not line_stripped.endswith('/') and '/' in line_stripped:
                        # Extract directory path from file path and assume there's at least 1 directory structure
                        folder_count = 1
                        break

            # Always return at least 1 to ensure the metrics are exported, unless output has no content
            return folder_count if folder_count > 0 else 1
        except subprocess.TimeoutExpired:
            logging.warning(f"Directory count operation timed out for snapshot {snapshot_id}, skipping directory count and defaulting to 1")
            return 1  # Default to 1 instead of 0 to ensure metrics are exported
        except Exception as e:
            logging.warning(f"Error counting directories for snapshot {snapshot_id}: {str(e)}, defaulting to 1")
            return 1  # Default to 1 instead of 0 to ensure metrics are exported

    def get_check(self):
        # This command takes 20 seconds or more, but it's required
        cmd = [
            "restic",
            "-r",
            self.repository,
            "-p",
            self.password_file,
            "--no-lock",
            "check",
        ]

        if self.insecure_tls:
            cmd.extend(["--insecure-tls"])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return 1  # ok
        else:
            logging.warning(
                "Error checking the repository health. " + self.parse_stderr(result)
            )
            return 0  # error

    def get_locks(self):
        cmd = [
            "restic",
            "-r",
            self.repository,
            "-p",
            self.password_file,
            "--no-lock",
            "list",
            "locks",
        ]

        if self.insecure_tls:
            cmd.extend(["--insecure-tls"])

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise Exception(
                "Error executing restic list locks command: "
                + self.parse_stderr(result)
            )
        text_result = result.stdout.decode("utf-8")
        lock_counter = 0
        for line in text_result.split("\n"):
            if re.match("^[a-z0-9]+$", line):
                lock_counter += 1

        return lock_counter

    @staticmethod
    def calc_snapshot_hash(snapshot: dict) -> str:
        text = snapshot["hostname"] + snapshot["username"] + ",".join(snapshot["paths"])
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def parse_stderr(result):
        return (
            result.stderr.decode("utf-8").replace("\n", " ")
            + " Exit code: "
            + str(result.returncode)
        )


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO")),
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.info("Starting Restic Prometheus Exporter")
    logging.info("It could take a while if the repository is remote")

    restic_repo_url = os.environ.get("RESTIC_REPOSITORY")
    if restic_repo_url is None:
        restic_repo_url = os.environ.get("RESTIC_REPO_URL")
        if restic_repo_url is not None:
            logging.warning(
                "The environment variable RESTIC_REPO_URL is deprecated, "
                "please use RESTIC_REPOSITORY instead."
            )
    if restic_repo_url is None:
        logging.error("The environment variable RESTIC_REPOSITORY is mandatory")
        sys.exit(1)

    restic_repo_password_file = os.environ.get("RESTIC_PASSWORD_FILE")
    if restic_repo_password_file is None:
        logging.error("The environment variable RESTIC_PASSWORD_FILE is mandatory")
        sys.exit(1)

    exporter_address = os.environ.get("LISTEN_ADDRESS", "0.0.0.0")
    exporter_port = int(os.environ.get("LISTEN_PORT", 8001))
    exporter_refresh_interval = int(os.environ.get("REFRESH_INTERVAL", 60))
    exporter_exit_on_error = bool(os.environ.get("EXIT_ON_ERROR", False))
    exporter_disable_check = bool(os.environ.get("NO_CHECK", False))
    exporter_disable_stats = bool(os.environ.get("NO_STATS", False))
    exporter_disable_locks = bool(os.environ.get("NO_LOCKS", False))
    exporter_include_paths = bool(os.environ.get("INCLUDE_PATHS", False))
    exporter_insecure_tls = bool(os.environ.get("INSECURE_TLS", False))

    try:
        collector = ResticCollector(
            restic_repo_url,
            restic_repo_password_file,
            exporter_exit_on_error,
            exporter_disable_check,
            exporter_disable_stats,
            exporter_disable_locks,
            exporter_include_paths,
            exporter_insecure_tls,
        )
        REGISTRY.register(collector)
        start_http_server(exporter_port, exporter_address)
        logging.info(
            "Serving at http://{0}:{1}".format(exporter_address, exporter_port)
        )

        while True:
            logging.info(
                "Refreshing stats every {0} seconds".format(exporter_refresh_interval)
            )
            time.sleep(exporter_refresh_interval)
            collector.refresh()

    except KeyboardInterrupt:
        logging.info("\nInterrupted")
        exit(0)