cc = meson.get_compiler('c')
math_dep = cc.find_library('m', required: false)
math_deps = math_dep.found() ? [math_dep] : []
math_link_args = math_dep.found() ? ['-lm'] : []
picoquic_inc = include_directories('..' / 'subprojects' / 'picoquic' / 'picoquic')
test_env = environment()
if enable_asan
  test_env.set('LSAN_OPTIONS', 'detect_leaks=0')
endif

inline_dots_test = executable(
  'slipstream-inline-dots-test',
  files(
    'slipstream_inline_dots_test.c',
    '..' / src / 'slipstream_inline_dots.c',
  ),
  include_directories: include_dirs,
  build_by_default: false,
)

test(
  'slipstream-inline-dots',
  inline_dots_test,
  env: test_env,
)

utils_test = executable(
  'slipstream-utils-test',
  files(
    'slipstream_utils_test.c',
    '..' / src / 'slipstream_utils.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: include_dirs,
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-utils',
  utils_test,
  env: test_env,
)

sockloop_test = executable(
  'slipstream-sockloop-test',
  files(
    'slipstream_sockloop_test.c',
    '..' / src / 'slipstream_sockloop.c',
  ),
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args,
  build_by_default: false,
)

test(
  'slipstream-sockloop-core',
  sockloop_test,
  env: test_env,
)

client_ctx_test = executable(
  'slipstream-client-ctx-test',
  common_sources + files(
    'slipstream_client_ctx_test.c',
    'slipstream_client_ctx_wrapper.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-client-ctx',
  client_ctx_test,
  env: test_env,
)

server_ctx_test = executable(
  'slipstream-server-ctx-test',
  common_sources + files(
    '..' / src / 'slipstream_server_cc.c',
    'slipstream_server_ctx_test.c',
    'slipstream_server_ctx_wrapper.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-server-ctx',
  server_ctx_test,
  env: test_env,
)

server_cc_test = executable(
  'slipstream-server-cc-test',
  files(
    'slipstream_server_cc_test.c',
    '..' / src / 'slipstream_server_cc.c',
  ),
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args,
  build_by_default: false,
)

test(
  'slipstream-server-cc',
  server_cc_test,
  env: test_env,
)

integration_test = executable(
  'slipstream-integration-test',
  common_sources + files(
    'slipstream_integration_test.c',
    'slipstream_client_codec_wrapper.c',
    'slipstream_server_codec_wrapper.c',
    '..' / src / 'slipstream_server_cc.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: include_dirs,
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-integration',
  integration_test,
  env: test_env,
)

loopback_integration_test = executable(
  'slipstream-loopback-integration-test',
  common_sources + files(
    'slipstream_loopback_integration_test.c',
    'slipstream_client_integration_wrapper.c',
    'slipstream_server_integration_wrapper.c',
    '..' / src / 'slipstream_server_cc.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-loopback-integration',
  loopback_integration_test,
  env: test_env,
)

client_test = executable(
  'slipstream-client-test',
  common_sources + files(
    'slipstream_client_test.c',
    '..' / src / 'slipstream_client.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: include_dirs,
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-client-core',
  client_test,
  env: test_env,
)

server_test = executable(
  'slipstream-server-test',
  common_sources + files(
    'slipstream_server_test.c',
    '..' / src / 'slipstream_server.c',
    '..' / src / 'slipstream_server_cc.c',
  ),
  dependencies: slipstream_cli_deps + math_deps,
  include_directories: include_dirs,
  link_args: link_args + math_link_args,
  build_by_default: false,
)

test(
  'slipstream-server-core',
  server_test,
  env: test_env,
)

cli_test = executable(
  'slipstream-cli-test',
  files('slipstream_cli_test.cpp'),
  dependencies: slipstream_cli_deps,
  include_directories: include_dirs,
  link_args: link_args,
  build_by_default: false,
)

test(
  'slipstream-cli-args',
  cli_test,
  env: test_env,
)

cli_main_test = executable(
  'slipstream-cli-main-test',
  files(
    'slipstream_cli_main_test.cpp',
    '..' / src / 'slipstream_utils.c',
  ),
  include_directories: [include_dirs, picoquic_inc],
  link_args: link_args,
  build_by_default: false,
)

test(
  'slipstream-cli-main',
  cli_main_test,
  env: test_env,
)
