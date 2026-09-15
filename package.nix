{ lib, rustPlatform, libfido2, openssl, cryptsetup, python3 }:
rustPlatform.buildRustPackage {
  pname = "luks-combo-unlock";
  version = "0.2.2";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
  buildInputs = [ libfido2 openssl cryptsetup ];
  doCheck = true;
  nativeCheckInputs = [ python3 ];
  postCheck = ''
    python3 tests/terminal.py target/x86_64-unknown-linux-gnu/release/deps
  '';
  meta = {
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "luks-combo-unlock";
  };
}
