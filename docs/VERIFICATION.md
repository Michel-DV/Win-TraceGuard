# Verification strategy

Win-TraceGuard's C11 claim is verified at build time, not only documented.

The migration was validated through repeated independent GitHub Actions runs on Windows/MSVC. Each run executes the same gates from a clean checkout:

- reject C++ source/header extensions;
- reject CXX CMake configuration;
- require C11 configuration;
- configure with CMake;
- compile the release executable with the MSVC C compiler;
- execute CTest;
- execute the version smoke test;
- execute the provider-configuration smoke test;
- replay the synthetic telemetry corpus and verify expected detection IDs.

The same CI also runs for pull requests and again after changes reach `main`, giving the project separate branch, integration and post-merge verification points.
