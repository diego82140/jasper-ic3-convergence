# Pinned interceptor build

The prebuilt launcher needs no Gum SDK. Offline producer rebuilding needs the optional rebuild-input archive, whose `third_party/frida-gum/ASSET.json` records the exact patched header/static-library hashes. Keep the Frida license with redistributions. The native library has a tested GLIBC 2.17 ceiling when built with the compatibility link or a suitable manylinux2014 builder; an arbitrary host rebuild can change that ceiling.

The SDK was generated from `https://github.com/frida/frida-gum` commit `22e077120358a49b26e32110a6e2b8e80f1ed7f1` with `third_party/gum-native-unwind-17.18.0.patch`. The patch applies exactly to six tracked upstream files. It supplies provider-specific unwind exports, owned installation rollback, generation/return-slot guards and native continuations for supported direct/indirect calls. Unsupported continuation forms decline observation. Native exception transparency remains unqualified for arbitrary asynchronous interruptions/private runtimes.

To generate the SDK in a new upstream checkout, check out that commit, initialize its pinned submodules, apply the packaged patch, and configure with:

```bash
./configure --with-frida-version=17.18.0 --with-devkits=gum --disable-tests
make
```

GumJS/Gum++ are disabled by default; the retained build used the prefixed static Gum devkit and assertions disabled. Configuration can download pinned toolchain/SDK inputs. The observed build produced `build/gum/devkit/frida-gum.h` and `libfrida-gum.a`. A complete clean network rebuild is distinct from the tested offline producer rebuild; do not claim byte-identical debug information across source paths. Copy the generated devkit into `third_party/frida-gum`, verify/update its receipt, then build in an idle plugin clone. Fresh native M/M4 checks are required for the resulting artifact.

The packaged-source offline rebuild matched all allocated sections of the candidate except the build-id note, and required GLIBC at most 2.17. That comparison does not replace native qualification. Reproduction receipts and finite exception/ownership fixtures are retained in the validation ledger.
