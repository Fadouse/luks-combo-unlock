{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "luks-combo-unlock";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
  doCheck = true;
  meta = {
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "luks-combo-unlock";
  };
}
