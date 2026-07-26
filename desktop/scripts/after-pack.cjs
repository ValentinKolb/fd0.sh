const { execFileSync } = require("node:child_process");
const { join } = require("node:path");

module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== "darwin") return;

  const plist = join(
    context.appOutDir,
    `${context.packager.appInfo.productFilename}.app`,
    "Contents",
    "Info.plist",
  );

  for (const key of ["NSAllowsArbitraryLoads", "NSAllowsLocalNetworking"]) {
    execFileSync("plutil", ["-replace", `NSAppTransportSecurity.${key}`, "-bool", "NO", plist]);
  }
  for (const key of [
    "NSAppTransportSecurity.NSExceptionDomains",
    "NSAudioCaptureUsageDescription",
    "NSBluetoothAlwaysUsageDescription",
    "NSBluetoothPeripheralUsageDescription",
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
  ]) {
    try {
      execFileSync("plutil", ["-remove", key, plist], { stdio: "ignore" });
    } catch {
      // Electron versions differ in which unused permission strings they add.
    }
  }
};
