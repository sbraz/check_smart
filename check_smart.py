#!/usr/bin/env python3.7
"""A Nagios-like plugin to check devices' SMART status"""
import argparse
import collections
import hashlib
import json
import logging
import os
import pathlib
import pickle
import re
import shlex
import stat
import subprocess
import sys

import nagiosplugin  # type: ignore

logger = logging.getLogger("nagiosplugin")


class Smart(nagiosplugin.Resource):
    checked_metrics = (
        "ata_smart_error_log_count",
        "Calibration_Retry_Count",
        "critical_comp_time",
        "critical_warning",
        "Current_Pending_Sector",
        "CRC_Error_Count",
        "ECC_Error_Rate",
        "Erase_Fail_Count_Total",
        "G-Sense_Error_Rate",
        "Load_Retry_Count",
        "media_errors",
        "Multi_Zone_Error_Rate",
        "num_err_log_entries",
        "Offline_Uncorrectable",
        "Program_Fail_Cnt_Total",
        "Raw_Read_Error_Rate",
        "Reallocated_Event_Count",
        "Reallocated_Sector_Ct",
        "Runtime_Bad_Block",
        "Seek_Error_Rate",
        "Spin_Retry_Count",
        "UDMA_CRC_Error_Count",
        "Uncorrectable_Error_Cnt",
        "Used_Rsvd_Blk_Cnt_Tot",
        "warning_temp_time",
    )

    def __init__(self, args, unique_hash):
        self.args = args
        self.unique_hash = unique_hash
        self.metrics = {}
        self.old_metrics = {}

    def check_metric(self, serial, metric, value, temperature=False):
        # Ignore all raw temperature metrics because
        # we obtain them from the "Current temperature" section
        if not temperature and re.match(r"^temperature($|_)", metric, flags=re.I):
            return
        try:
            values = self.old_metrics[serial][metric]
        except KeyError:
            values = []
        values.append(value)
        if len(values) > (self.args.max_attempts + 1):
            values.pop(0)
        self.metrics[serial][metric] = values
        metric_str = "[{}] {} = {}".format(serial, metric, value)
        if metric in self.checked_metrics:
            if self.args.checked_metrics:
                print(metric_str)
            for i in range(1, len(values)):
                if values[i] > values[i - 1] and metric not in self.args.exclude_metric:
                    yield nagiosplugin.Metric(
                        "warning",
                        {"increment": (serial, metric, values[i - 1], values[i])},
                        context="metadata",
                    )
        elif self.args.non_checked_metrics:
            print(metric_str)
        logger.info(metric_str)
        yield nagiosplugin.Metric("{}_{}".format(serial, metric), value, context="smart_attributes")

    def list_devices(self):
        devices = []
        selected_devices_absolute = []
        for dev in self.args.devices:
            try:
                selected_devices_absolute.append(dev.resolve())
            # Don't raise a RuntimeError if an infinite loop is encountered
            # to minimize the risk of information leakage
            except Exception:  # pylint: disable=broad-except
                pass
        for path in pathlib.Path("/sys/block/").iterdir():
            if not (path / "device").is_dir():
                continue
            try:
                with (path / "device/type").open() as f:
                    scsi_type = int(f.read())
            # If there is no type file, assume it is a disk
            # https://github.com/karelzak/util-linux/blob/2089538a/misc-utils/lsblk.c#L431
            except FileNotFoundError:
                scsi_type = 0
            with (path / "size").open() as f:
                dev_size = int(f.read())
            dev_path = pathlib.Path("/dev") / path.name

            if self.args.skip_removable:
                try:
                    with (path / "removable").open() as f:
                        removable = int(f.read())
                    if removable == 1:
                        continue
                except Exception:  # pylint: disable=broad-except
                    pass

            # SCSI_TYPE_DISK, see
            # https://github.com/torvalds/linux/blob/d1fdb6d8/include/scsi/scsi_proto.h#L251
            if scsi_type == 0x00 and dev_size != 0:
                # selected_devices_absolute might be empty if some devices were
                # unresolvable, so we use the non-absolute list in the condition.
                # Otherwise, a list of unresolvable devices would be the same as
                # no filter at all and we don't want that.
                if not self.args.devices or dev_path in selected_devices_absolute:
                    devices.append(dev_path)
        return devices

    def parse_exit_status(self, device, serial, exit_status):
        bits = [(exit_status >> _) & 1 for _ in range(8)]
        if bits[0]:
            raise nagiosplugin.CheckError("Command line did not parse for {}".format(device))
        if bits[1]:
            raise nagiosplugin.CheckError("Device open failed for {}".format(device))
        if bits[2]:
            if not self.args.ignore_failing_commands:
                yield nagiosplugin.Metric(
                    "warning",
                    {
                        "status": (
                            serial or device,
                            "a command failed or a checksum error was found",
                        )
                    },
                    context="metadata",
                )
        if bits[3]:
            yield nagiosplugin.Metric(
                "critical", {"status": (serial or device, "in failing state")}, context="metadata"
            )
        if bits[4]:
            yield nagiosplugin.Metric(
                "critical",
                {"status": (serial or device, "has prefail attributes below threshold")},
                context="metadata",
            )
        if bits[5]:
            yield nagiosplugin.Metric(
                "warning",
                {
                    "status": (
                        serial or device,
                        "had prefail attributes below threshold at some point",
                    )
                },
                context="metadata",
            )
        if bits[7]:
            yield nagiosplugin.Metric(
                "warning",
                {"status": (serial or device, "last sef-test returned errors")},
                context="metadata",
            )

    def _load_cookie(self, state_file):
        # Make sure that the cookie can't be read by non-root users
        os.umask(0o077)
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            try:
                self.old_metrics = cookie["metrics"]
            except KeyError:
                yield nagiosplugin.Metric(
                    "warning",
                    {"message": "No data in state file {}, first run?".format(state_file)},
                    context="metadata",
                )

    def _save_cookie(self, state_file):
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            cookie["metrics"] = self.metrics

    def _get_device_smart_data(self, device):
        if self.args.load_json:
            smart_data = json.load(sys.stdin)
        else:
            command = ["smartctl", "--json=s", "-x", str(device)]
            logger.info("Running command: %s", " ".join(shlex.quote(_) for _ in command))
            proc = subprocess.run(  # pylint: disable=subprocess-run-check
                command, capture_output=True, universal_newlines=True
            )
            smart_data = json.loads(proc.stdout)
        return smart_data

    @classmethod
    def _handle_smart_messages(cls, device, smart_data):
        for msg in smart_data["smartctl"].get("messages", []):
            if msg["severity"] == "error":
                raise nagiosplugin.CheckError(
                    "smartctl returned an error for {}: {}".format(device, msg["string"])
                )

    def _handle_other_metrics(self, smart_data, serial):
        if smart_data["device"]["type"] == "sat":
            for attr in smart_data["ata_smart_attributes"]["table"]:
                yield from self.check_metric(serial, attr["name"], attr["raw"]["value"])
        elif smart_data["device"]["type"] == "nvme":
            for attr, attr_val in smart_data["nvme_smart_health_information_log"].items():
                if isinstance(attr_val, list):
                    for i, val in enumerate(attr_val):
                        yield from self.check_metric(serial, "{}_{}".format(attr, i), val)
                else:
                    yield from self.check_metric(serial, attr, attr_val)

    def _probe_device(self, device):
        smart_data = self._get_device_smart_data(device)
        self._handle_smart_messages(device, smart_data)
        # We want to be able to split perfdata on the first underscore to extract the serial
        try:
            serial = smart_data["serial_number"].replace("_", "-")
        except KeyError:
            serial = None
        yield from self.parse_exit_status(device, serial, smart_data["smartctl"]["exit_status"])
        # Create a metric based on the number of errors in the log
        if "ata_smart_error_log" in smart_data:
            yield from self.check_metric(
                serial,
                "ata_smart_error_log_count",
                smart_data["ata_smart_error_log"]["extended"]["count"],
            )
        # Parse temperature separately because sometimes
        # the raw value includes "Min/Max" strings and isn't usable
        try:
            yield from self.check_metric(
                serial, "temperature", smart_data["temperature"]["current"], temperature=True
            )
        except Exception:  # pylint: disable=broad-except
            pass
        # Parse all other metrics
        yield from self._handle_other_metrics(smart_data, serial)

    def probe(self):
        if not self.args.load_json:
            valid_devices = self.list_devices()
            if not valid_devices:
                raise nagiosplugin.CheckError(
                    "Could not find any device matching {}".format(
                        ", ".join(str(_) for _ in self.args.devices)
                    )
                )
        self.metrics = collections.defaultdict(dict)
        state_file = pathlib.Path("/var/tmp") / ".check_smart_{}".format(self.unique_hash)
        if state_file.is_file() and any(
            (
                state_file.owner() != "root",
                state_file.group() != "root",
                (state_file.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0,
            )
        ):
            raise nagiosplugin.CheckError(
                "Permissions on state file {} are too open".format(state_file)
            )
        self._load_cookie(state_file)
        if self.args.load_json:
            valid_devices = [None]
        for dev in valid_devices:
            yield from self._probe_device(dev)
        self._save_cookie(state_file)


class SmartSummary(nagiosplugin.Summary):
    def ok(self, results):
        return ""

    def verbose(self, results):
        # We handle verbose with the logger, the summary doesn't change based on verbosity
        pass

    @classmethod
    def _handle_result(cls, result, messages, increments, disk_statuses):
        if result.state == nagiosplugin.Ok:
            return
        if "increment" in result.hint:
            serial, metric, old_val, new_val = result.hint["increment"]
            increments[serial][metric] = (old_val, new_val)
        elif "message" in result.hint:
            messages.append(result.hint["message"])
        elif "status" in result.hint:
            serial, msg = result.hint["status"]
            disk_statuses[serial].append(msg)
        # Handle all other messages (including those originating from CheckError)
        else:
            messages.append(result.hint)

    def problem(self, results):
        messages = []
        increments = collections.defaultdict(dict)
        disk_statuses = collections.defaultdict(list)
        # Worst result first
        for result in sorted(results, key=lambda x: x.state, reverse=True):
            self._handle_result(result, messages, increments, disk_statuses)
        for serial, status_messages in disk_statuses.items():
            messages.append("Disk {}: {}".format(serial, ", ".join(status_messages)))
        for serial, serial_increments in increments.items():
            inc_messages = []
            for metric, (old, new) in serial_increments.items():
                inc_messages.append("{}: {} -> {}".format(metric, old, new))
            messages.append(
                "Disk {}: increment in counter{} {}".format(
                    serial, "" if len(inc_messages) == 1 else "s", ", ".join(inc_messages)
                )
            )
        return ", ".join(messages)


class MetaDataContext(nagiosplugin.Context):
    # pylint: disable=inconsistent-return-statements
    def evaluate(self, metric, resource):
        if metric.name == "warning":
            return self.result_cls(nagiosplugin.Warn, metric.value)
        if metric.name == "critical":
            return self.result_cls(nagiosplugin.Critical, metric.value)


# No traceback display during argiment parsing
@nagiosplugin.guarded(verbose=0)
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-D",
        "--devices",
        help="limit to specific devices",
        type=pathlib.Path,
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "--skip-removable", help="skip removable devices", action="store_true", default=False
    )
    parser.add_argument(
        "-v", "--verbose", help="enable more verbose output", default=0, action="count"
    )
    parser.add_argument(
        "--max-attempts",
        help="number of attempts required for the service to enter a hard state,"
        " this controls the number of values retained for each counter",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--exclude-metric",
        action="append",
        default=[],
        help="exclude the following metric when checking for increments",
    )
    parser.add_argument(
        "--ignore-failing-commands",
        help="ignore the second bit of smartctl's exit status, indicating that "
        "a command failed or a checksum error was found",
        action="store_true",
        default=False,
    )
    # We load from stdin to prevent users from reading any file
    # on the system since the script runs as root
    parser.add_argument(
        "--load-json",
        help="load smartctl's JSON output from stdin for debugging purposes",
        action="store_true",
        default=False,
    )
    checked_metrics_grp = parser.add_mutually_exclusive_group()
    checked_metrics_grp.add_argument(
        "--checked-metrics",
        help="print checked metrics and their values for debugging purposes",
        action="store_true",
        default=False,
    )
    checked_metrics_grp.add_argument(
        "--non-checked-metrics",
        help="print non-checked metrics and their values for debugging purposes",
        action="store_true",
        default=False,
    )
    return parser.parse_args()


@nagiosplugin.guarded
def main(args):
    # Unique identifier used to store check state
    relevant_args = []
    for arg, arg_val in sorted(vars(args).items()):
        if arg not in ("verbose",):
            relevant_args.append((arg, arg_val))
    args_hash = hashlib.sha1(pickle.dumps(relevant_args)).hexdigest()
    check = nagiosplugin.Check(
        Smart(args, args_hash),
        nagiosplugin.ScalarContext("smart_attributes"),
        MetaDataContext("metadata"),
        SmartSummary(),
    )
    check.main(args.verbose)


if __name__ == "__main__":
    main(parse_args())
