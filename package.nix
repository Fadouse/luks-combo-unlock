{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "luks-session-guard";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
  doCheck = true;
  meta = {
    description = "LUKS combination unlock and fail-closed desktop autologin orchestration";
    homepage = "https://github.com/Fadouse/luks-session-guard";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
    mainProgram = "luks-session-guard";
  };
}
