boost_test = dependency('boost', required: false, modules: ['unit_test_framework'])
ntl = cc.find_library('ntl', required: false, has_headers: ['NTL/version.h'])

# Aggregate signature smoke tests, one executable per parameter set.
# Each runs the full 5-round protocol at n=1 and n=3 plus tamper + pk-
# substitution negative checks. No Boost dependency.
foreach parameter_set : parameter_sets
  smoke_src = configure_file(
    input: 'aggregate_smoke_test.c.in',
    output: 'aggregate_smoke_test_@0@.c'.format(parameter_set.get('PARAM_L')),
    configuration: parameter_set,
  )
  smoke_exe = executable(
    'aggregate_smoke_test_@0@'.format(parameter_set.get('PARAM_L')),
    smoke_src,
    dependencies: [get_variable('libfaest_@0@_dependency'.format(parameter_set.get('PARAM_L')))],
    include_directories: include_directories,
    c_args: defines + c_flags,
  )
  test(
    'AggregateSmoke_@0@'.format(parameter_set.get('PARAM_L')),
    smoke_exe,
    timeout: 600,
  )
endforeach

if boost_test.found()
  test_sources = files(
    'aes.cpp',
    # 'aes_prove.cpp',
    'bavc.cpp',
    'extended_tests.cpp',
    'fields.cpp',
    'hash_shake.cpp',
    'instances.cpp',
    'owf.cpp',
    'prg.cpp',
    'universal_hashing.cpp',
    'utils.cpp',
    'vole.cpp',
  )
  test_deps = []
  test_defines = ['-DBOOST_TEST_DYN_LINK', '-DFAEST_TESTS']
  if ntl.found()
    test_deps += ntl
    test_defines += ['-DHAVE_NTL']
  endif

  foreach parameter_set : parameter_sets
    test_sources += configure_file(
      input: 'basic.cpp.in',
      output: 'faest_@0@_basic.cpp'.format(parameter_set.get('PARAM_L')),
      configuration: parameter_set,
    )
  endforeach

  extended_tests = executable(
    'test_extended_tests',
    test_sources,
    dependencies: [libfaest_static_dependency, boost_test] + test_deps,
    include_directories: include_directories,
    cpp_args: defines + cpp_flags + test_defines,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
  test(
    'AES',
    extended_tests,
    args: ['-t', 'aes'],
    timeout: 6000,
  )
  # only useful for debugging
  # test(
  #   'AES prove',
  #   extended_tests,
  #   args: ['-t', 'test_aes_prove'],
  #   timeout: 6000,
  # )
  test(
    'SHAKE',
    extended_tests,
    args: ['-t', 'hash_shake'],
    timeout: 6000,
  )
  test(
    'Instances',
    extended_tests,
    args: ['-t', 'instances'],
    timeout: 6000,
  )
  test(
    'OWF',
    extended_tests,
    args: ['-t', 'owf'],
    timeout: 6000,
  )
  test(
    'PRG',
    extended_tests,
    args: ['-t', 'prgs'],
    timeout: 6000,
  )
  test(
    'Universal hashing',
    extended_tests,
    args: ['-t', 'universal_hashing'],
    timeout: 6000,
  )
  test(
    'Utils',
    extended_tests,
    args: ['-t', 'utils'],
    timeout: 6000,
  )
  test(
    'BAVC',
    extended_tests,
    args: ['-t', 'bavc'],
    timeout: 6000,
  )
  test(
    'VOLE',
    extended_tests,
    args: ['-t', 'vole'],
    timeout: 6000,
  )
  if ntl.found()
    test(
      'Fields',
      extended_tests,
      args: ['-t', 'fields'],
      timeout: 6000,
    )
  endif
  foreach parameter_set : parameter_sets
    test(
      'FAEST_@0@'.format(parameter_set.get('PARAM')),
      extended_tests,
      args: ['-t', 'faest_@0@'.format(parameter_set.get('PARAM_L'))],
      timeout: 6000,
    )
  endforeach
endif

if get_option('tv-generators').enabled()
  executable(
    'generate_bavc_tv',
    files('generate_bavc_tv.cpp'),
    dependencies: [libfaest_static_dependency],
    include_directories: include_directories,
    cpp_args: defines + test_defines + cpp_flags,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
  executable(
    'generate_prg_tv',
    files('generate_prg_tv.cpp'),
    dependencies: [libfaest_static_dependency],
    include_directories: include_directories,
    cpp_args: defines + test_defines + cpp_flags,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
  executable(
    'generate_owf_tv',
    files('generate_owf_tv.cpp'),
    dependencies: [libfaest_static_dependency],
    include_directories: include_directories,
    cpp_args: defines + test_defines + cpp_flags,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
  executable(
    'generate_vole_tv',
    files('generate_vole_tv.cpp'),
    dependencies: [libfaest_static_dependency],
    include_directories: include_directories,
    cpp_args: defines + test_defines + cpp_flags,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
  executable(
    'generate_universal_hashing_tv',
    files('generate_universal_hashing_tv.cpp'),
    dependencies: [libfaest_static_dependency],
    include_directories: include_directories,
    cpp_args: defines + test_defines + cpp_flags,
    link_args: linker_flags,
    override_options: ['b_lto=false'],
  )
endif