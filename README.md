# Introduction

This plugin can be used to monitor disks and detect changes in S.M.A.R.T. metrics.

## Features
* Checks the status of all smart metrics and whether they are in a failing state
* Checks increments in critical counters such as read errors
* Outputs performance data for all attributes

By default, the script checks all disks present on the system and
retains values over the last 4 runs. This means that in case a critical
metric sees an increase, the check will return a warning 4 times.
After the fifth run, the increment will no longer be detected.


# Requirements

The script requires:
* Python 3.10 or newer
* [`nagiosplugin`](https://nagiosplugin.readthedocs.io) version 1.2.4 or newer
* smartmontools 7.0 or newer (JSON output support)
* sudo and access to `smartctl --json=s -x` commands, see [the related section](#security)
* read-write access to `/var/tmp/` (where the state file is created)

# <a name="security"></a> Security considerations

In order to limit the attack surface as much as possible, it is recommended to
only grant sudo access to the required `smartctl` commands.

For example, create `/etc/sudoders.d/check_smart` containing:
```
icinga ALL=(ALL) NOPASSWD: /usr/sbin/smartctl --json=s -x /dev/sd[a-z]
icinga ALL=(ALL) NOPASSWD: /usr/sbin/smartctl --json=s -x /dev/sd[a-z][a-z]
icinga ALL=(ALL) NOPASSWD: /usr/sbin/smartctl --json=s -x /dev/nvme[0-9]n[0-9]
```

This should be enough to make the check work with most configurations.

# Usage

To check all disks:
```
./check_smart.py
```

To list all available disks:
```
./check_smart.py --list-devices
```

To limit to two disks:
```
./check_smart.py -D /dev/sda /dev/sdb
```

Symlinks are also resolved, so the following trick can be used
to make sure we are opening the same disk across reboots:
```
./check_smart.py -D /dev/disk/by-id/ata-*<device serial>
```

To exclude a disk:
```
./check_smart.py -X /dev/sda
```

It is possible to change the number of check attempts before an increment in a
checked counter stops being reported as an error. The following will cause
the check to return an error only once. All subsequent runs will be fine.
```
./check_smart.py --max-attempts 1
```

Sometimes, it is desirable to exclude certain counters from alerts:
```
./check_smart.py --exclude-metric Raw_Read_Error_Rate
```

The list of checked and non-checked metrics for a certain device
can be obtained with:
```
./check_smart.py --checked-metrics -D /dev/sda
./check_smart.py --non-checked-metrics -D /dev/sda
```

Check the help for a description of all avaliable options:
```
./check_smart.py -h
```

# Integration with Icinga

An Icinga `CheckCommand` can be defined with:
```
object CheckCommand "smart_metrics" {
  command = [PluginDir + "/check_smart.py"]
  arguments = {
    "--devices" = {
      value = "$smart_metrics_devices$"
      repeat_key = false
    }
    "--exclude-devices" = {
      value = "$smart_metrics_exclude_devices$"
      repeat_key = false
    }
    "--skip-removable" = {
      set_if = "$smart_metrics_skip_removable$"
    }
    "--max-attempts" = "$max_check_attempts$"
    "--exclude-metrics" = {
      value = "$smart_metrics_exclude_metrics$"
      repeat_key = false
    }
    "--ignore-failing-commands" = {
      set_if = "$smart_metrics_ignore_failing_commands$"
    }
    "--ignore-error-message" = {
        value = "$smart_metrics_ignore_error_message$"
    }
  }
  vars.smart_metrics_skip_removable = true
}
```
