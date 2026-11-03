#!/bin/zsh
# Builds Dolkoon.app next to this script (and copies it to ~/Applications).
set -e
cd "${0:A:h}"
APP=Dolkoon.app
rm -rf $APP
mkdir -p $APP/Contents/MacOS $APP/Contents/Resources
swiftc -O -parse-as-library -target arm64-apple-macos14 Sources/*.swift -o $APP/Contents/MacOS/Dolkoon
cat > $APP/Contents/Info.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Dolkoon</string>
  <key>CFBundleDisplayName</key><string>Dolkoon</string>
  <key>CFBundleIdentifier</key><string>app.dolkoon</string>
  <key>CFBundleExecutable</key><string>Dolkoon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
[ -f AppIcon.icns ] && cp AppIcon.icns $APP/Contents/Resources/
codesign -s - --force $APP >/dev/null 2>&1 || true
rm -rf ~/Applications/$APP && cp -R $APP ~/Applications/
echo "built $PWD/$APP"
