{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }@inputs:
    let
      inherit (nixpkgs) lib;

      forAllSystems =
        function:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system: function nixpkgs.legacyPackages.${system}
        );
    in
    {
      packages = forAllSystems (pkgs: rec {
        go-away = pkgs.buildGoModule rec {
          pname = "go-away";
          version = "git";
          src = ./.;
          vendorHash = "sha256-dqjjDlDkeek1qnqs9DtlU/r42et5P7RvNfv9MdptsrQ=";
        };
        default = go-away;
      });
      apps = forAllSystems (pkgs: {
        go-away = {
          type = "app";
          program = "${pkgs.lib.getExe pkgs.go-away}";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.system}.go-away ];
        };
      });
    };
}
