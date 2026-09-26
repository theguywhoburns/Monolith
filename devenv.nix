{ pkgs, config, ... }:
let
  graphicsLibs = with pkgs; [
    wayland
    libffi
    wayland-protocols
    vulkan-headers
    vulkan-loader
    vulkan-validation-layers
  ];
  graphicsTools = with pkgs; [
    wayland-scanner
    vulkan-tools
  ];

  # The kernel UAPI headers, sanitised the same way a distro does it.
  #
  # `make headers` runs include/asm-offsets-ish generators and produce
  # include/generated/{autoconf.h,compile.h,utsrelease.h}, and it flattens
  # arch/x86/include/asm into usr/include/asm. The result is a single directory
  # where <asm/unistd.h>, <asm/types.h> and <linux/types.h> all resolve, so the
  # build needs exactly one -isystem and no include/asm -> asm symlink games.
  #
  # This is NOT pkgs.linuxPackages.kernel.dev: that is the in-tree kernel build
  # directory, full of headers that need linux/kconfig.h and only make sense
  # when compiled by the kernel's own build system.
  linuxUapiHeaders = pkgs.stdenv.mkDerivation {
    pname = "linux-uapi-headers";
    version = pkgs.linux.version;
    src = pkgs.linux.src;

    strictDeps = true;
    nativeBuildInputs = with pkgs; [ gnumake gnutar xz gnused gnugrep findutils coreutils ];

    dontConfigure = true;
    dontFixup = true;

    buildPhase = ''
      runHook preBuild
      mkdir source
      tar xf $src --strip-components=1 -C source
      cd source
      make -j $NIX_BUILD_CORES ARCH=x86 headers
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      find usr/include -name '.*' -delete
      mkdir -p $out
      cp -r usr/include $out/
      runHook postInstall
    '';

    meta = {
      description = "Linux kernel UAPI headers";
      license = pkgs.lib.licenses.gpl2Only;
      platforms = pkgs.lib.platforms.linux;
    };
  };
in
{
  # clang, not gcc: -nostdlibinc drops the libc headers while keeping the
  # compiler's own freestanding ones (stddef.h, stdarg.h, stdint.h).
  stdenv = pkgs.llvmPackages.libcxxStdenv;

  packages = with pkgs; [
    git
    cmake
    ninja
    pkg-config
    lld                  # ld.lld
    llvm                 # llvm-objdump
    binutils             # readelf, objdump, nm
    linuxUapiHeaders
  ] ++ graphicsLibs ++ graphicsTools;

  # The one and only header search path for the build.
  env.LINUX_HEADERS = "${linuxUapiHeaders}/include";

  env.VULKAN_SDK = "${pkgs.vulkan-headers}";
  env.VK_LAYER_PATH = "${pkgs.vulkan-validation-layers}/share/vulkan/explicit_layer.d";
  env.VK_ADD_LAYER_PATH = "${pkgs.vulkan-validation-layers}/share/vulkan/explicit_layer.d";

  languages.c = {
    enable = true;
    lsp = {
      enable = true;
      package = pkgs.clang-tools;
    };
    debugger = pkgs.lldb;
  };

  enterShell = ''
    export CC=${config.stdenv.cc}/bin/cc
    export CXX=${config.stdenv.cc}/bin/c++
  '';

  # `devenv tasks run` does not enter the shell, so every task that needs
  # $LINUX_HEADERS, cmake or ninja has to depend on devenv:enterShell.
  tasks = {
    # before enterShell, not after: clangd needs build/compile_commands.json to
    # exist the moment an editor attaches, and configure is idempotent and fast
    # enough to be worth running unconditionally.
    "monolith:configure" = {
      before = [ "devenv:enterShell" ];
      exec = ''
        cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
      '';
    };

    "monolith:bld" = {
      after = [ "monolith:configure" ];
      exec = "cmake --build build";
    };

    "monolith:run" = {
      after = [ "monolith:bld" ];
      exec = "./build/monolith";
    };

    # Real tests, via CTest. --output-on-failure prints the checker's report
    # only when something actually breaks.
    "monolith:test" = {
      after = [ "monolith:bld" ];
      exec = ''
        ctest --test-dir build --output-on-failure "$@"
      '';
    };

    # The whole point of the project in one task: if all of this is clean,
    # then no C library, no CRT and no dynamic loader reached the link.
    "monolith:check" = {
      after = [ "monolith:bld" ];
      exec = ''
        echo "--- file (want: statically linked, ET_EXEC) ---"
        file build/monolith
        echo "--- undefined symbols (want: nothing) ---"
        nm -u build/monolith
        echo "--- dynamic section (want: no dynamic section) ---"
        readelf -d build/monolith
        echo "--- program headers (want: no PT_INTERP, no RWX) ---"
        readelf -lW build/monolith
      '';
    };

    "monolith:disasm" = {
      after = [ "monolith:bld" ];
      exec = "objdump -d -M intel build/monolith";
    };

    "monolith:clean".exec = "rm -rf build";
  };
}
