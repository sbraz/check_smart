#!/usr/bin/env python3.7
import os
import sys
import argparse
import subprocess
import pathlib
import json
import logging
import stat
import collections
import pickle
import hashlib

logger = logging.getLogger('nagiosplugin')

import nagiosplugin

# See https://github.com/torvalds/linux/blob/d1fdb6d8f6a4109a4263176c84b899076a5f8008/include/scsi/scsi_proto.h#L251
SCSI_TYPE_DISK = 0x00

class Smart(nagiosplugin.Resource):
    checked_metrics = (
        'Calibration_Retry_Count',
        'critical_warning',
        'Current_Pending_Sector',
        'media_errors',
        'Multi_Zone_Error_Rate',
        'num_err_log_entries',
        'Offline_Uncorrectable',
        'Raw_Read_Error_Rate',
        'Reallocated_Event_Count',
        'Reallocated_Sector_Ct',
        'Seek_Error_Rate',
        'Spin_Retry_Count',
        'UDMA_CRC_Error_Count'
    )
    def __init__(self, args, unique_hash):
        self.args = args
        self.unique_hash = unique_hash
    def check_metric(self, serial, metric, value, metrics, old_metrics):
        try:
            values = old_metrics[serial][metric]
        except KeyError:
            values = []
        values.append(value)
        if len(values) > self.args.retention:
            values.pop(0)
        metrics[serial][metric] = values
        if metric in self.checked_metrics:
            for i in range(1, len(values)):
                if values[i] > values[i-1]:
                    yield nagiosplugin.Metric("warning", {"increment": (serial, metric, values[i-1], values[i])}, context="metadata")
        logger.info("[{}] {} = {}".format(serial, metric, value))
        yield nagiosplugin.Metric("{}_{}".format(serial, metric), value, context="smart_attributes")
    def list_devices(self):
        devices = []
        selected_devices_absolute = []
        for d in self.args.devices:
            try:
                selected_devices_absolute.append(d.resolve())
            # Don't raise a RuntimeError if an infinite loop is encountered
            # to minimize the risk of information leakage
            except:
                pass
        for p in pathlib.Path("/sys/block/").iterdir():
            if not (p / "device").is_dir():
                continue
            try:
                with (p / "device/type").open() as f:
                    scsi_type = int(f.read())
            # If there is no type file, assume it is a disk
            # https://github.com/karelzak/util-linux/blob/2089538adb1116d59be797f663bba059a5236b8a/misc-utils/lsblk.c#L431
            except FileNotFoundError:
                scsi_type = 0
            with (p / "size").open() as f:
                dev_size = int(f.read())
            dev_path = pathlib.Path("/dev") / p.name
            if scsi_type == SCSI_TYPE_DISK and dev_size != 0:
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
            yield nagiosplugin.Metric("warning", {"status": (serial or device, "a command failed or a checksum error was found")}, context="metadata")
        if bits[3]:
            yield nagiosplugin.Metric("critical", {"status": (serial or device, "in failing state")}, context="metadata")
        if bits[4]:
            yield nagiosplugin.Metric("critical", {"status": (serial or device, "has prefail attributes below threshold")}, context="metadata")
        if bits[5]:
            yield nagiosplugin.Metric("warning", {"status": (serial or device, "had prefail attributes below threshold at some point")}, context="metadata")
        if bits[7]:
            yield nagiosplugin.Metric("warning", {"status": (serial or device, "last sef-test returned errors")}, context="metadata")
    def probe(self):
        valid_devices = self.list_devices()
        if not valid_devices:
            raise nagiosplugin.CheckError("Could not find any device matching {}".format(", ".join(str(_) for _ in self.args.devices)))
        metrics = collections.defaultdict(dict)
        state_file = pathlib.Path("/var/tmp") / ".check_smart_{}".format(self.unique_hash)
        if state_file.is_file() and any((state_file.owner() != "root", state_file.group() != "root", (state_file.stat().st_mode & (stat.S_IRWXG|stat.S_IRWXO)) != 0)):
            raise nagiosplugin.CheckError("Permissions on state file {} are too open".format(state_file))
        # Make sure that the cookie can't be read by non-root users
        os.umask(0o077)
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            try:
                old_metrics = cookie["metrics"]
            except KeyError:
                yield nagiosplugin.Metric("warning", {"message": "No data in state file {}, first run?".format(state_file)}, context="metadata")
                old_metrics = {} 
        for d in valid_devices:
            command = ["smartctl", "--json=s", "-x", str(d)]
            logger.info("Running command {}".format(command))
            p = subprocess.run(command, capture_output=True, universal_newlines=True)
            smart_data = json.loads(p.stdout)
            for msg in smart_data["smartctl"].get("messages", []):
                if msg["severity"] == "error":
                    raise nagiosplugin.CheckError("smartctl returned an error for {}: {}".format(d, msg["string"]))
            # We want to be able to split perfdata on the first underscore to extract the serial
            try:
                serial = smart_data["serial_number"].replace("_", "-")
            except:
                serial = None
            yield from self.parse_exit_status(d, serial, smart_data["smartctl"]["exit_status"])
            if "ata_smart_error_log" in smart_data:
                yield from self.check_metric(serial, "ata_smart_error_log_count", smart_data["ata_smart_error_log"]["extended"]["count"], metrics, old_metrics)
            if smart_data["device"]["type"] == "sat":
                for attr in smart_data["ata_smart_attributes"]["table"]:
                    yield from self.check_metric(serial, attr["name"], attr["raw"]["value"], metrics, old_metrics)
            elif smart_data["device"]["type"] == "nvme":
                for attr, attr_val in smart_data["nvme_smart_health_information_log"].items():
                    if isinstance(attr_val, list):
                        for i, v in enumerate(attr_val):
                            yield from self.check_metric(serial, "{}_{}".format(attr, i), v, metrics, old_metrics)
                    else:
                        yield from self.check_metric(serial, attr, attr_val, metrics, old_metrics)
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            cookie["metrics"] = metrics

class SmartSummary(nagiosplugin.Summary):
    def ok(self, results):
        return ""
    def verbose(self, results):
        # We handle verbose outside of the summary 
        pass
    def problem(self, results):
        msgs = []
        increments = collections.defaultdict(dict)
        disk_statuses = collections.defaultdict(list)
        # Worst result first
        for result in sorted(results, key=lambda x: x.state, reverse=True):
            if result.state == nagiosplugin.Ok:
                continue
            if "increment" in result.hint:
                serial, metric, old_val, new_val = result.hint["increment"]
                increments[serial][metric] = (old_val, new_val)
            elif "message" in result.hint:
                msgs.append(result.hint["message"])
            elif "status" in result.hint:
                serial, msg = result.hint["status"]
                disk_statuses[serial].append(msg)
            # Handle all other messages (including those originating from CheckError)
            else:
                msgs.append(result.hint)
        for serial, status_msgs in disk_statuses.items():
            msgs.append("Disk {}: {}".format(serial, ", ".join(status_msgs)))
        for serial, serial_increments in increments.items():
            inc_msgs = []
            for metric, (old, new) in serial_increments.items():
                inc_msgs.append("{}: {} -> {}".format(metric, old, new))
            msgs.append("Disk {}: increment in counters {}".format(serial, ", ".join(inc_msgs)))
        return ", ".join(msgs)


class MetaDataContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        if metric.name == "warning":
            return self.result_cls(nagiosplugin.Warn, metric.value)
        elif metric.name == "critical":
            return self.result_cls(nagiosplugin.Critical, metric.value)

# No traceback display during argiment parsing
@nagiosplugin.guarded(verbose=0)
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-D", "--devices", help="limit to specific devices", type=pathlib.Path, nargs="+", default=[])
    parser.add_argument("-v", "--verbose", help="enable more verbose output", default=0, action="count")
    parser.add_argument("--retention", help="number of previous values to retain, must be equal to or greater than the max check attempts to let the service enter a hard state", type=int, default=3)
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
            SmartSummary()
    )
    check.main(args.verbose)
    return

if __name__ == "__main__":
    args = parse_args()
    main(args)
