{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default-linux";

    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    systems,
    gomod2nix,
    ...
  }: let
    eachSystem = nixpkgs.lib.genAttrs (import systems);
    getGoVer = system: nixpkgs.legacyPackages.${system}.go_1_24;
  in {
    formatter = eachSystem (system: nixpkgs.legacyPackages.${system}.alejandra);

    packages = eachSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      goVer = getGoVer system;
    in {
      default = self.packages.${system}.go-away;
      go-away = pkgs.callPackage ./nix/package.nix {
        go = goVer;
        inherit pkgs;
        inherit (gomod2nix.legacyPackages.${system}) buildGoApplication;
      };
    });

    devShells = eachSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        goVer = getGoVer system;
        goEnv = gomod2nix.legacyPackages.${system}.mkGoEnv {
          pwd = ./.;
          go = goVer;
        };
      in {
        default = self.devShells.${system}.go-away;
        go-away = pkgs.mkShell {
          name = "go-away-dev";
          packages = [
            goVer
            goEnv
            gomod2nix.legacyPackages.${system}.gomod2nix
          ];
        };
      }
    );
  };
}
