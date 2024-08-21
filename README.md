# apk-tools

Alpine Package Keeper (apk) is a package manager originally built for Alpine Linux,
but now used by several other distributions as well.

## Building

The preferred build system for building apk-tools is Meson:

```
# meson setup build --prefix=/
# meson compile -C build
# meson install -C build
```

For bootstrapping without Python, muon is also compatible. All you have to do is replace `meson` with `muon` in the above example.

While there is a legacy Makefile-based system available, it only works for musl-linux
targets, and will be dropped in the apk-tools 3.0 release.

## Documentation

Online documentation is available in the [doc/](doc/) directory in the form of man pages.

The [apk(8)](doc/apk.8.scd) man page provides a basic overview of the package management
system.
