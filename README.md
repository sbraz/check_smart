# Introduction

This plugin can be used to monitor disks and detect changes in S.M.A.R.T. metrics.
It checks two things:
* The status of all smart metrics and whether they are in a failing state.
* Increments in critical counters such as read errors.

By default, the script checks all devices present on the system and
retains values over the last 4 runs. This means that in case a critical
metric sees an increase, the check will return a warning 4 times.
After the fifth run, the increment will no longer be detected.

# Usage

To check all disks:
```
./check_smart.py
```

To limit to two disks:
```
./check_smart.py -D /dev/sda /dev/sdb
```

Symlinks are also followed, so the following trick can be used
to make sure we are opening the right device:
```
./check_smart.py -D /dev/disk/by-id/ata-*<device serial>
```

Sometimes, it is desirable to exclude certain counters from alertes:
```
./check_smart.py --exclude-metric Raw_Read_Error_Rate
```

The list of checked and non-checked metrics for a certain device
can be obtained with:
```
./check_smart.py --checked-metrics -D /dev/sda
./check_smart.py --non-checked-metrics -D /dev/sda
```

Check the help for all options:
```
./check_smart.py -h
```

# Requirements

The script requires:
* Python 3.7 or newer
* [`nagiosplugin`](https://nagiosplugin.readthedocs.io) version 1.2.4 or newer
* smartmontools 7.0 or newer (JSON output support)
* root access (for `smartctl` to work)
* read-write access to `/var/tmp/` (where the state file is created)

# Integration with Icinga

An Icinga `CheckCommand` can be defined with:
```
object CheckCommand "smart_metrics" {
  command = ["sudo", PluginDir + "/check_smart.py"]
  arguments = {
    "--max-attempts" = "$max_check_attempts$"
    "--skip-removable" = {
      set_if = "$smart_metrics_skip_removable$"
    }
    "--ignore-failing-commands" = {
      set_if = "$smart_metrics_ignore_failing_commands$"
    }
    "--exclude-metric" = {
      value = "$smart_metrics_exclude_metric$"
      repeat_key = true
    }
  }
  vars.smart_metrics_skip_removable = true
}
```
