{ lib, rustPlatform, libfido2, openssl, cryptsetup }:
rustPlatform.buildRustPackage {
  pname = "luks-combo-unlock";
  version = "0.2.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
  buildInputs = [ libfido2 openssl cryptsetup ];
  doCheck = true;
  meta = {
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "luks-combo-unlock";
  };
}
