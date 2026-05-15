# Set up a C and C++ project with useful defaults for debugging
project(
  'slipstream',
  ['c', 'cpp'],
  version: '0.1.0',
  license: 'Apache-2.0',
  meson_version: '>=1.0.0',
  default_options: [
    'buildtype=release',  # Changed from debugoptimized to release for max performance
    'cpp_std=gnu++11',
    'c_std=gnu11',
    'default_library=shared',
    'warning_level=everything',
    'b_lto=true',  # Link-time optimization ENABLED
  ],
)

# Aliases to significant locations in the source tree
src = 'src'
extern = 'extern'
lua_resty = extern / 'lua-resty-base-encoding'
quick_args = extern / 'quick_arg_parser'
spcdns = extern / 'SPCDNS' / src

# Sources common to both client and server
common_sources = files(
  src / 'slipstream_sockloop.c',
  src / 'slipstream_utils.c',
  src / 'slipstream_inline_dots.c',
  src / 'slipstream_optimizations.c',  # NEW: Optimization implementations
  lua_resty / 'base32.c',
  spcdns / 'codec.c',
  spcdns / 'mappings.c',
  spcdns / 'netsimple.c',
  spcdns / 'output.c',
)

# Various directories with headers for the sources
include_dirs = include_directories('include', extern, quick_args, spcdns, lua_resty)

# Default linker arguments
link_args = []

# Set up static links
is_static = get_option('default_library') == 'static'
if is_static and host_machine.system() != 'darwin'
  link_args = [
    '-static-libgcc',
    '-static-libstdc++',
  ]
endif

# Performance optimization flags
add_project_arguments(
  [
    '-O3',                    # Maximum optimization
    '-march=native',          # CPU-specific instructions
    '-ffast-math',            # Faster math operations
    '-funroll-loops',         # Loop unrolling
    '-fno-strict-aliasing',   # Aliasing assumptions
    '-flto=auto',             # LTO with auto parallelization
  ],
  language: ['c', 'cpp']
)

# Additional optimizations for release build
if get_option('buildtype') == 'release'
  add_project_arguments(
    [
      '-DNDEBUG',                    # Disable asserts
      '-fomit-frame-pointer',        # Save stack space
      '-finline-functions',          # Function inlining
      '-ffunction-sections',         # Section per function
      '-fdata-sections',             # Section per data
    ],
    language: ['c', 'cpp']
  )
  link_args += ['-Wl,--gc-sections']  # Garbage collect unused sections
endif

# Import the CMake module
cmake = import('cmake')

# Get the cmake options objects
picoquic_opts = cmake.subproject_options()

# Add necessary CMake defines
picoquic_opts.add_cmake_defines(
  [
    {'PICOQUIC_FETCH_PTLS': 'ON'},
    {'BUILD_HTTP': 'OFF'},
    {'ENABLE_ASAN': 'OFF'},
    {'ENABLE_UBSAN': 'OFF'},
    {'CMAKE_POLICY_VERSION_MINIMUM': '3.5'},
    {'BUILD_DEMO': 'OFF'},
    {'BUILD_TESTING': 'OFF'},
  ],
)
# Configure picoquic debug printing
if get_option('buildtype').startswith('debug')
  picoquic_opts.add_cmake_defines(
    {'DISABLE_DEBUG_PRINTF': 'OFF'},
  )
else
  picoquic_opts.add_cmake_defines(
    {'DISABLE_DEBUG_PRINTF': 'ON'},
  )
endif
# Configure optional picoquic logging
loglib_enabled = get_option('build_loglib')
if loglib_enabled
  picoquic_opts.add_cmake_defines(
    {'BUILD_LOGREADER': 'ON'},
  )
  add_project_arguments('-DBUILD_LOGLIB', language: ['c', 'cpp'])
else
  picoquic_opts.add_cmake_defines(
    {'BUILD_LOGREADER': 'OFF'},
  )
endif

# Reference picoquic as a CMake subproject
picoquic_proj = cmake.subproject(
  'picoquic',
  options: picoquic_opts,
)

# Dependencies used by both executables
slipstream_cli_deps = [
  dependency('threads'), # for picoquic
  picoquic_proj.dependency('picoquic-core'),
]
# Link optional picoquic logging
if loglib_enabled
  slipstream_cli_deps += picoquic_proj.dependency('picoquic-log')
endif

# Sources only used by client
client_sources = files(
  src / 'slipstream_client.c',
  src / 'slipstream_client_cli.cpp',
)

# Sources only used by server
server_sources = files(
  src / 'slipstream_server.c',
  src / 'slipstream_server_cc.c',
  src / 'slipstream_server_cli.cpp',
)

# The final client executable
executable(
  'slipstream-client',
  client_sources + common_sources,
  dependencies: slipstream_cli_deps,
  include_directories: include_dirs,
  link_args: link_args,
  build_by_default: true,
)

# The final server executable
executable(
  'slipstream-server',
  server_sources + common_sources,
  dependencies: slipstream_cli_deps,
  include_directories: include_dirs,
  link_args: link_args,
  build_by_default: true,
)
