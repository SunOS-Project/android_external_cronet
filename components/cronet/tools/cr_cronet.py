#!/usr/bin/env python3
# Copyright 2014 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
cr_cronet.py - cr - like helper tool for cronet developers
"""

import argparse
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime


def quoted_args(args):
  return ' '.join([shlex.quote(arg) for arg in args])


def run(command, **kwargs):
  print(command, kwargs)
  return subprocess.call(command, **kwargs)


def run_shell(command, extra_options=''):
  command = command + ' ' + extra_options
  print(command)
  return os.system(command)


def gn(out_dir, gn_args, gn_extra=None):
  cmd = ['gn', 'gen', out_dir, '--args=%s' % gn_args]
  if gn_extra:
    cmd += gn_extra
  return run(cmd)


def build(out_dir, build_target, extra_options=None):
  cmd = ['ninja', '-C', out_dir, build_target] + get_ninja_jobs_options()
  if extra_options:
    cmd += extra_options
  return run(cmd)


def install(out_dir):
  cmd = ['build/android/adb_install_apk.py']
  # Propagate PATH to avoid issues with missing tools http://crbug/1217979
  env = {
      'BUILDTYPE': out_dir[4:],
      'PATH': os.environ.get('PATH', '')
  }
  return run(cmd + ['CronetTestInstrumentation.apk'], env=env) or \
      run(cmd + ['ChromiumNetTestSupport.apk'], env=env)


def test(out_dir, extra_options):
  # Ideally we would fetch this path from somewhere. Though, that's not trivial
  # and very unlikely to change. This being "best effort test code", it should
  # be fine just to hardcode it.
  remote_netlog_dir = '/data/data/org.chromium.net.tests/app_cronet_test/NetLog'
  run(['adb', 'shell', 'rm', '-rf', remote_netlog_dir])
  run([out_dir + '/bin/run_cronet_test_instrumentation_apk'] + extra_options)
  local_netlog_dir = out_dir + '/netlogs_for-' + datetime.now().strftime(
      "%y_%m_%d-%H_%M_%S")
  return run(['adb', 'pull', remote_netlog_dir, local_netlog_dir])


def unittest(out_dir, extra_options):
  return run([out_dir + '/bin/run_cronet_unittests_android'] +
             extra_options)


def debug(extra_options):
  return run(['build/android/adb_gdb', '--start',
             '--activity=.CronetTestActivity',
             '--program-name=CronetTest',
             '--package-name=org.chromium.net'] +
             extra_options)


def stack(out_dir):
  return run_shell('adb logcat -d | CHROMIUM_OUTPUT_DIR=' +
                   shlex.quote(out_dir) +
                   ' third_party/android_platform/development/scripts/stack')


def use_goma():
  goma_dir = (subprocess.check_output(['goma_ctl', 'goma_dir'])
                        .decode('utf-8')
                        .strip())
  result = run(['goma_ctl', 'ensure_start'])
  if not result:
    return 'use_goma=true goma_dir="' + goma_dir + '" '
  return ''


def get_ninja_jobs_options():
  if use_goma():
    return ["-j1000"]
  return []


def map_config_to_android_builder(is_release, target_cpu):
  target_cpu_to_base_builder = {
      'x86': 'android-cronet-x86',
      'x64': 'android-cronet-x64',
      'arm': 'android-cronet-arm',
      'arm64': 'android-cronet-arm64',
      'riscv64': 'android-cronet-riscv64',
  }
  if target_cpu not in target_cpu_to_base_builder:
    raise ValueError('Unsupported target CPU')

  builder_name = target_cpu_to_base_builder[target_cpu]
  if is_release:
    builder_name += '-rel'
  else:
    builder_name += '-dbg'
  return builder_name


def filter_gn_args(gn_args):
  gn_arg_matcher = re.compile("^.*=.*$")
  # `mb_py lookup` prints out a bunch of metadata lines which we don't
  # care about, we only want the GN args.
  assert len(gn_args) > 4
  actual_gn_args = gn_args[1:-3]
  for line in gn_args:
    if line in actual_gn_args:
      assert gn_arg_matcher.match(line), \
             f'Not dropping {line}, which does not look like a GN arg'
    else:
      assert not gn_arg_matcher.match(line), \
             f'Dropping {line}, which looks like a GN arg'

  return list(filter(lambda string: "remoteexec" not in string, actual_gn_args))


def android_gn_gen(is_release, target_cpu, out_dir):
  group_name = 'chromium.android'
  mb_script = 'tools/mb/mb.py'
  builder_name = map_config_to_android_builder(is_release, target_cpu)
  # Ideally we would call `mb_py gen` directly, but we need to filter out the
  # use_remoteexec arg, as that cannot be used in a local environment.
  gn_args = subprocess.check_output([
      'python3', mb_script, 'lookup', '-m', group_name, '-b', builder_name
  ]).decode('utf-8').strip()
  gn_args = filter_gn_args(gn_args.split("\n"))
  return gn(out_dir, ' '.join(gn_args))


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('command',
                      choices=['gn',
                               'sync',
                               'build',
                               'install',
                               'proguard',
                               'test',
                               'build-test',
                               'unit',
                               'build-unit',
                               'stack',
                               'debug',
                               'build-debug'])
  parser.add_argument('-d', '--out_dir', action='store',
                      help='name of the build directory')
  parser.add_argument('-x', '--x86', action='store_true',
                      help='build for Intel x86 architecture')
  parser.add_argument('--x64',
                      action='store_true',
                      help='build for Intel x86_64 architecture')
  parser.add_argument('-R',
                      '--riscv64',
                      action='store_true',
                      help='build for riscv64 architecture')
  parser.add_argument('-r', '--release', action='store_true',
                      help='use release configuration')
  parser.add_argument('-a', '--asan', action='store_true',
                      help='use address sanitizer')

  options, extra_options = parser.parse_known_args()
  print("Options:", options)
  print("Extra options:", extra_options)

  test_target = 'cronet_test_instrumentation_apk'
  unit_target = 'cronet_unittests_android'
  if options.x86:
    target_cpu = 'x86'
    out_dir_suffix = '-x86'
  elif options.x64:
    target_cpu = 'x64'
    out_dir_suffix = '-x64'
  elif options.riscv64:
    target_cpu = 'riscv64'
    out_dir_suffix = '-riscv64'
  else:
    target_cpu = 'arm64'
    out_dir_suffix = '-arm64'

  if options.asan:
    # ASAN on Android requires one-time setup described here:
    # https://www.chromium.org/developers/testing/addresssanitizer
    out_dir_suffix += '-asan'

  if options.out_dir:
    out_dir = options.out_dir
  else:
    if options.release:
      out_dir = 'out/Release' + out_dir_suffix
    else:
      out_dir = 'out/Debug' + out_dir_suffix

  if (options.command=='gn'):
    return android_gn_gen(options.release, target_cpu, out_dir)
  if (options.command=='sync'):
    return run(['git', 'pull', '--rebase']) or run(['gclient', 'sync'])
  if (options.command=='build'):
    return build(out_dir, test_target, extra_options)
  if (options.command == 'install'):
    return install(out_dir)
  if (options.command == 'proguard'):
    return build(out_dir, 'cronet_sample_proguard_apk')
  if (options.command == 'test'):
    return install(out_dir) or test(out_dir, extra_options)
  if (options.command == 'build-test'):
    return build(out_dir, test_target) or install(out_dir) or \
        test(out_dir, extra_options)
  if (options.command == 'stack'):
    return stack(out_dir)
  if (options.command == 'debug'):
    return install(out_dir) or debug(extra_options)
  if (options.command == 'build-debug'):
    return build(out_dir, test_target) or install(out_dir) or \
        debug(extra_options)
  if (options.command == 'unit'):
    return unittest(out_dir, extra_options)
  if (options.command == 'build-unit'):
    return build(out_dir, unit_target) or unittest(out_dir, extra_options)

  parser.print_help()
  return 1


if __name__ == '__main__':
  sys.exit(main())
