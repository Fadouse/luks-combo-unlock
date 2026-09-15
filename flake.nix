{
  description = "LUKS combination unlock and guarded Niri autologin";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAll = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAll (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.callPackage ./package.nix { }; });
      checks = forAll (system: { build = self.packages.${system}.default; });
      devShells = forAll (system:
        let pkgs = import nixpkgs { inherit system; };
        in { default = pkgs.mkShell { packages = [ pkgs.cargo pkgs.rustc pkgs.rustfmt ]; }; });
    };
}
