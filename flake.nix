{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.callPackage ./package.nix {};
    checks.x86_64-linux.default = self.packages.x86_64-linux.default;
    nixosModules.default = import ./nixos-module.nix;
  };
}
