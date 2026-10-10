# Native headers and runtime libraries for Linux verification.
{ pkgs ? import (builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436.tar.gz";
  sha256 = "sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=";
}) {} }:
let
  sdk = builtins.fromJSON (builtins.readFile ./native-sdk.json);
  # The reviewed upstream static artifact matches the locked Rust SDK ABI.
  # BB_LIB_DIR disables its build script's implicit download/build path.
  bbSource = pkgs.fetchurl {
    url = "https://github.com/AztecProtocol/barretenberg/releases/download/v${sdk.version}/barretenberg-static-amd64-linux.tar.gz";
    sha256 = sdk.sha256;
  };
  bbLibrary = pkgs.runCommand "barretenberg-static-${sdk.version}" {} ''
    mkdir -p "$out/lib"
    tar -xzf ${bbSource} -C "$out/lib" libbb-external.a
  '';
in pkgs.mkShell {
  buildInputs = with pkgs; [
    llvmPackages.libclang.lib
    llvmPackages.libcxx
  ];
  nativeBuildInputs = with pkgs; [
    pkg-config
    clang
    llvmPackages.libclang
  ];
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  BB_LIB_DIR = "${bbLibrary}/lib";
  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.llvmPackages.libclang.lib pkgs.llvmPackages.libcxx ]}:''${LD_LIBRARY_PATH:-}";
  '';
}
