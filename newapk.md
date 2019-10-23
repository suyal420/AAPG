 My primary goal with this repo is to define a comprehensive Android application penetration testing guide. This is an operational guide with the intention to assist you while performing a pentest.

I will provide what I've learned / will learn at work and share it here with you. To improve this guide, I would highly appreciate your help with everything you have successfully used in the wild and/or experienced so far at work.

Gitbook-Link

I followed this OWASP Mobile Security Testing Guide and tried to summarize it.

Download the aapg.txt here

===========================================================================
============================== 0) Used Tools ==============================
===========================================================================

a) apktool
    -) AUR package: yay -S android-apktool
b) dex2jar
c) jd-gui
d) jadx
e) adb
    -) sudo pacman -S android-tools
    -) I personally would recommend installing android-studio (it comes with the SDK - including all platform-tools)
        o) sudo pacman -S andriod-studio
f) bettercap
    -) sudo pacman -S bettercap
g) dnSpy
    -) .NET decompiler (in case of Xamarin Apps)
h) enjarify
i) apk decompiler for lazy: https://github.com/b-mueller/apkx

==========================================================================
===================== 1) MANUAL STATIC ANALYSIS ==========================
==========================================================================
////////////////
1a) RETRIEVE APK
////////////////

    FROM THE DEVICE ITSELF
        [COMMANDS]
            o) adb shell pm list packages (list all installed packages)
            o) adb shell pm path com.x.x.x (display apk path of package)
            o) adb pull /data/data/com.x.x.x/app_name.apk (copy the apk file to your system)

    APK DOWNLOADER
        1) Search for your application @ https://play.google.com/store
        2) Copy URL (i.e: https://play.google.com/store/apps/details?id=com.whatsapp)
        3) Paste URL into one of the downloaders below or one of your own choice: 
            o) evozi
            o) pureapkapp (recommended)
            o) apkmirror
/////////////////
1b) DECOMPILE APK
/////////////////

    UNZIP (I'm aware this is just unpacking - not decompiling)
        [COMMANDS]
            o) unzip app_name.apk
        [INFO]
            -) quick & dirty way
            -) Manifest.xml is not readable
            -) However .dex files can be found -> d2j-dex2jar
            -) certs + signature-files available

    APKTOOL
        [COMMANDS]
            o) apktool d path/to/your/app_name.apk (decompiles .dex files to .smali)
            o) apktool d --no-src app_name.apk (does NOT decompile .dex files to .smali)
        [INFO]
            -) not all files do get extracted: i.e certs + signature files & more are missing

    DEX2JAR
        [COMMANDS]
            o) d2j-dex2jar app_name.apk
        [INFO]
            -) extracts decompiled .jar only & app_name-error.zip (open with jd-gui)

    JADX
        [COMMANDS]
            o) jadx -d path/to/extract/ --deobf app_name.apk (jadx-deobfuscator -> deobfs simple obf. code)
            o) jadx -d path/to/extract/ app_name.apk
            o) jadx -d path/to/extract/ classes.dex (outputs .java files at path/to/extract/sources/)
        [INFO]
            -) RECOMMENDED!!
            -) resources + sources available (source code + certs, ...)

    DEOBFUSCATION
        [COMMANDS]
            o) jadx -d path/to/extract/ --deobf app_name.apk
            o) simplify -i file_name.smali -o class.dex
        [INFO]
            -) no 100% success guaranteed --> works only with simple obfuscated files 
            -) to get the file_name.smali --> decompile with APKTOOL

    XAMARIN
        [COMMANDS]
            o) 7z e app_name.apk (unzip apk and retrieve *.dll files)
        [INFO]
            -) Xamarin Apps are written in C#, therefore you have to decompile it on a windows machine (i.e. dnSpy)
            -) Main Code can be found in app_name.dll (but usually there are more too)

/////////////////////
1c) CHECK CERTIFICATE
/////////////////////

    [COMMANDS]
        o) openssl pkcs7 -inform DER -in META-INF/*.RSA -noout -print_certs -text
        o) jarsigner -verify -verbose -certs app_name.apk (optional)

    [INFO]    
        -) jarsigner --> huge output (each file gets validated)
        -) cert location:
            -) unzip.apk --> META-INF/*.RSA
            -) jadx app_name.apk --> resources/META-INF/*.RSA
        -) custom CAs may be definded: res/xml/network_security_config.xml (or similar name)
            -) also cert-pinning info available there (i.e expiration)

    [THINGS TO REPORT]
        !) CN=Android Debug (=debug cert -> public known private key)
        !) CA is expired
        !) The CA that issued the server certificate was unknown
        !) CA was self signed
        !) The server configuration is missing an intermediate CA
        !) no cert-pinning (public key pinning) enabled (if you are able to route traffic through a proxy)
        !) cleartext Traffic is allowed (until Android 8.1): 
            -) <base-config cleartextTrafficPermitted="true">
            -) <domain-config cleartextTrafficPermitted="true">

    [MORE DETAILS]
        ?) Manifest permissions
        ?) SSL common problems
        ?) ssltest

///////////////////////////////
1d) ANALYZE ANDROIDMANIFEST.XML
///////////////////////////////

    [COMMANDS]
        RETRIEVE MANIFEST ONLY (already covered if you have properly decompiled the app)
            o) aapt dump app_name.apk AndroidManifest.xml > manifest.txt
            o) aapt l -a app_name.apk > manifest.txt
            o) run app.package.manifest com.x.x.x (within drozer-shell "dr>")

        CREATE BACKUP
            o) adb backup -all -apk -shared (full backup)
            o) adb backup com.x.x.x (single app backup)
            o) decode unencrypted backup
                o) xxd backup.ab (check if encrypted --> if you see "none" --> not encrypted)
                o) dd if=all-data.ab bs=24 skip=1 | openssl zlib -d > all-data.tar
                    o) tar xvf all-data.tar (extract tar-archive)
        
    [INFO]
        APPLICATION OVERVIEW
            -) <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28"/> (Version & Requirements)
            -) <activity android:name="com.x.x.x....MainActivity" ... > (existing activities)
            -) <service android:name="com.x.x.x....SampleService" ... > (used services --> find class which interacts with external resources and databases)

        PERMISSIONS
            -) <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>

        DEBUG APPLICATION
            -) Debugging running apps or processes with GDB 
        
    [THINGS TO REPORT]
        !) Wrong version/requirements specified
        !) android:allowBackup = TRUE
        !) android:debuggable = TRUE
        !) andorid:exported= TRUE or not set at all (within <provider>-Tag) --> allows external app to access data
        !) android.permission.WRITE_EXTERNAL_STORAGE / READ_EXTERNAL_STORAGE (ONLY IF sensitive data was stored/read externally)
        !) inproper use of permissions
            !) e.g. the app opens website in external browser (not inApp), however requires "android.permission.INTERNET" --> false usage of permissions. (over-privileged)
            !) "android:protectionLevel" was not set properly (<permission android:name="my_custom_permission_name" android:protectionLevel="signature"/>)
            !) missing android:permission (permission tags limit exposure to other apps)
    [MORE DETAILS]
        ?) Application elements
        ?) Security guidelines for AndroidManifest
        ?) Android Platform Releases

////////////////////////
1e) SOURCE CODE ANALYSIS
////////////////////////

    [COMMANDS]
        THINGS TO SEARCH FOR QUICKLY
            o) grep -Ei 'api' -Ei 'http' -Ei 'https' -Ei 'URI' -Ei 'URL' -R . (recursive search for endpoints)
            o) grep -Eio '(http|https)://[^/"]+' -Eio 'content://[^/"]+' -R . (check if strings follow a URL pattern)
            o) grep -Ei 'MODE_WORLD_READABLE' -Ei 'MODE_WORLD_WRITEABLE' -R . (check if improper file permissions were set within the code)
            o) grep -Ei 'getCacheDir' -Ei 'getExternalCacheDirs' -R . (check if sensitive files get saved in cache)
            o) grep -Ei 'localUserSecretStore' -Ei 'getWriteableDatabase' -Ei 'getReadableDatabase' -Ei 'SQLiteDatabase' -Ei 'realm' -Ei 'getDefaultInstance' -Ei 'beginTransaction' -Ei 'insert' -Ei 'query' -Ei 'delete' -Ei 'update' -R . (check for database related stuff)
            o) grep -Ei 'openFileOutput' -Ei 'FileOutputStream' -Ei 'OutputStream' -Ei 'getExternalFilesDir' -R . (check for file operation related stuff)
            o) grep -Ei 'AndroidKeystore' -Ei 'KeyStore' -Ei 'crypto' -Ei 'cipher' -Ei 'store' -R . (check for keystore related stuff)
            o) grep -Ei 'username' -Ei 'user' -Ei 'userid' -Ei 'password' -Ei '.config' -Ei 'secret' -Ei 'pass' -Ei 'passwd' -Ei 'token' -Ei 'login' -Ei 'auth' -R . (search for user related stuff)
            o) grep -Ei 'Log.v' -Ei 'Log.d' -Ei 'Log.i' -Ei 'Log.w' -Ei 'Log.e' -Ei 'log' -Ei 'logger' -Ei 'printStackTrace' -Ei 'System.out.print' -Ei 'System.err.print' -R . (log related stuff)
            o) grep -Ei 'Cursor' -Ei 'content' -Ei 'ContentResolver' -Ei 'CONTENT_URI' -Ei 'Loader' -Ei 'onCreateLoader' -Ei 'LoaderManager' -Ei -R . 
        
        OPEN SOURCE-CODE FILES
            o) jd-gui app-dex2jar.jar (opens .jar/.java/.class files) or use an IDE of your choice (android studio or eclipse)

    [INFO]
        INTERESTING CLASSES
            -) SharedPreferences (stores key-value pairs)
            -) FileOutPutStream (uses internal or external storage)

        INTERESTING FUNCTIONS
            -) getExternal* (uses external storage)
            -) getWriteableDatabase (returns SQLiteDB for writing)
            -) getReadableDatabase (returns SQLiteDB for reading)
            -) getCacheDir / getExternalCacheDirs (uses cached files)
        
    [THINGS TO REPORT]
        !) Cleartext credentials (includes base64 encoded or weak encrypted ones)
        !) Credentials cracked (brute-force, guessing, decrypted with stored cryptographic-key, ...)
        !) File permission MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE (other apps/users are able to read/write)
        !) If http is in use (no SSL)
        !) Anything that shouldn't be there (debug info, comments wiht info disclosure, ...)

==========================================================================
=================== 2) AUTOMATED STATIC ANALYSIS =========================
==========================================================================

    [RECOMMENDED TOOLS] 
        -) MobSF
        -) quark
        -) AndroBugs
        -) JAADAS

    [INFO]
        -) At this point you have to google yourself how to install and use them ;)
        -) MobSF + quark are recommended! 

==========================================================================
===================== 3) MANUAL DYNAMIC ANALYSIS =========================
==========================================================================
/////////////////
3a) prerequisites
/////////////////

    [PROXY]
        -) Install Burp-Suite (recommended)

        [AVD || ROOTED DEVICE]
            -) cert installation:
                ?) BEFORE Android 7 (Nougat)
                ?) Android 7 or higher
            -) Proxy setup
                ?) Virtual device
                ?) Physical phone

        [ADDITIONAL TOOLS]
            -) Install drozer on host & phone
            -) Android SDK
                !) adb might be located @ Android/Sdk/platform-tools/ (Linux)
        
        [FUNCTIONALITY TEST]
            COMMANDS:
                o) adb devices (should list your device)
                o) adb forward tcp:31415 tcp:31415 (port forwarding for drozer client)
                o) drozer console devices (list available drozer clients)
                o) drozer console connect (connect to drozer client and end up in drozer-shell: "dr>")

    [NON-PROXY AWARE APPS]
        -) Route traffic through the host machine (e.g. built-in Internet Sharing) --> Wireshark (cli: tshark) or tcpdump
            -) Downside - if HTTPS, you are not able to see any request bodies
            1) tcpdump -i <interface: wlan0> -s0 -w - | nc -l -p 11111 (remotely sniff via netcat)
            2) adb forward tcp:11111 tcp:11111
            3) nc localhost 11111 | wireshark -k -S -i -

        -) MitM with bettercap (same network as target device):
            -) sudo bettercap -eval "set arp.spoof.targets <TARGER-IP>; arps.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;" (command may defer due to bettercap version)
        
        -) Redirect with iptables:
            -) iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination <PROXY-IP>:8080
            -) verify iptables settings: iptables -t nat -L
            -) reset iptables config: iptables -t nat -F
        -) Hooking or Code-Injection

        [WHY?]
            -) In case of XAMARIN (ignores system proxy - not always! give it a try before you cry)
            -) Other protocols are used (XMPP or other non-HTTP)
            -) To intercept push notifications
            -) The app itself verifies connection and refuse  

////////////////////////////////
3b) INSTALL APPLICATION & USE IT
////////////////////////////////

    [COMMANDS]
        o) adb install path/to/app_name.apk
            o) In case it does not work:
                o) copy apk to phone and install it directly: adb push app_name.apk /sdcard/
                o) download apk on phone and install it ()

    [INFO]
        ------------------------------------------------------------
        !!!!!INTERCEPT THE WHOLE TRAFFIC FROM THE BEGINNING ON!!!!!!
        ------------------------------------------------------------
        Start using the app, like a normal user would
            o) Log in -> Browse around -> load content & so on ...
            o) Look for:
                o) File up/download
                    o) try to bypass fileupload/-filter (often there is only a client-side validation only)
                o) Activity behaviour & functionality
                o) ANYTHING which indicates a communication to a backend/api or might be stored locally
            o) check proxy and look for suspicious behaviour, requests, new/different endpoints & so on ...

/////////////////////
3c) BYPASS DETECTIONS
/////////////////////

    [SSL PINNING]
        !!! TBD soon !!! 

    [ROOT DETECTION]
        !!! TBD soon !!!

    [EMULATOR DETECTION]
        [COMMANDS]
            CHECK IF ONE IS PRESENT
                -) grep -Ei "isEmulator" -Ei "root" -Ei "carrierNameFromTelephonyManager" -Ei "smellsLikeAnEmulator" -Ei "SystemProperties" -R . (known methods)
                -) grep -Ei "build.fingerprint" -Ei "build.hardware" -Ei "product.kernel" -Ei "product.brand" -Ei "product.name" -Ei "product.model" -Ei "product.manufacturer" -Ei "product.device" -Ei "Emulator" -Ei "qemu.hw.mainkeys" -Ei "bootloader" -Ei "bootmode" -Ei "secure" -Ei "build.version.sdk" -R .
                -) grep -Ei "generic" -Ei "unknown" -Ei "google_sdk" -Ei "Android SDK built for x86" -Ei "Genymotion" -Ei "google_sdk" -Ei "goldfish" -R .
            
            BYPASS IT (IF PRESENT)
                1) check AVD || rooted device "values (depending what the code is demanding, you might need to modify them)
                    -) adb shell getprop ro.product.name
                    -) adb shell getprop ro.product.device
                    -) adb shell getprop ro.product.model
                    -) adb shell getprop ro.kernel.qemu
                    -) adb shell getprop ro.hardware
                    -) adb shell getprop qemu.hw.mainkeys
                    -) adb shell getprop ro.bootloader
                    -) adb shell getprop ro.bootmode
                    -) adb shell getprop ro.secure
                    -) adb shell getprop ro.build.fingerprint
                    -) adb shell getprop ro.build.version.sdk
                2) Modify the code, so YOUR values will pass the test || delete the whole validation (if possible)
                3) Recompile: apktool b ./modified_app_project_dir
                4) Sign apk: 
                    4.1) create key: keytool -genkey -v -keystore my-release-key.keystore -alias myalias  -keyalg RSA -keysize 2048 -validity 10000
                        !) remember the password you used
                    4.2) sign apk: /home/<user>/Android/Sdk/build-tools/<27.0.3_OR_CHECK_YOUR_USED_VERSION>/apksigner sign --ks my-release-key.keystore ./modified_app_project_dir/dist/modified_app.apk
                5) install apk on device: adb install /path/to/modified_app.apk
        
        [INFO]
            !) No 100% success guaranteed:
                !) there might be fancy solutions out there (appreciate any input here!!)
                !) In case of heavy obfuscation --> good look with that
                !) Very often the app will be delivered with a root detection as well
            !) The grep commands above search for known method-names or values which might get executed/checked on app-startup
        
        [MORE DETAILS]
            ?) Bypassing Android Emulator Part I
            ?) Bypassing Android Emulator Part II
            ?) Bypassing Android Emulator Part III 
           
        [THINGS TO REPORT]
            !) Bypassing the emulator detection is possible by simple code-tampering

/////////////////////////
3d) ANALYZE LOCAL STORAGE
/////////////////////////

    [COMMANDS]
        LOCAL DATABASE
            o) sqlite3 db_name (open database within adb-shell)
                o) in sqlite-terminal: 
                    o) .tables (lists all tables) --> SELECT * FROM table_name (show table content)
                    o) .schema table_name (shows columns)
                    o) SELECT sql FROM sqlite_master WHERE tbl_name = 'insert_table_name' AND type = 'table'; (see table creation query -> reveals columns as well)
            o) For .realm files:
                o) adb pull path/to/database/on/phone/name.realm path/to/store/db/on/pc/
                o) open within RealmStudio

    [INFO]
        COMMON LOCATIONS OF SECRETS/INFORMATION
            -) resources (i.e: res/values/strings.xml)
            -) build configs
            -) /data/data/<com.x.x.x>/ 
                -) shared_prefs/ (search for keysets -> used to encrypt files --> might be encrypted as well, if handled properly)
                -) cache/
                -) database/ (local sqlite database)
            -) /sdcard/Android/<com.x.x.x>/
        
        KEEP YOUR EYES OPEN
            -) developer files
            -) backup files
            -) old files

    [THINGS TO REPORT]
        !) Hardcoded cryptographics key
        !) Cleartext credentials stored in .config/.xml & sqlite-/realm-DB
        !) Misplaced files (i.e. creds.txt stored on SD-Card)
        !) Wrong file permissions set (also have a look @ 1e)

    [MORE DETAILS]
        ?) data storage security on android
