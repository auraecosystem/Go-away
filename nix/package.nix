{
  lib,
  go,
  pkgs,
  buildGoApplication,
}:
buildGoApplication {
  pname = "go-away";
  version = import ./version.nix;
  src = ../.;
  pwd = ../.;
  modules = ./gomod2nix.toml;
  subPackages = ["cmd/go-away"];
  inherit go;

  postPatch = ''
    patchShebangs build-compress.sh
  '';

  nativeBuildInputs = with pkgs; [
    # build-compress.sh
    brotli
    zopfli

    # build-wasm.sh
    tinygo
    writableTmpDirAsHomeHook
  ];

  preBuild = ''
    ./build-compress.sh

    # build-wasm.sh
    go generate ./...
  '';

  meta = {
    description = "Self-hosted abuse detection and rule enforcement against low-effort mass AI scraping and bots.";
    homepage = "https://git.gammaspectra.live/git/go-away";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
