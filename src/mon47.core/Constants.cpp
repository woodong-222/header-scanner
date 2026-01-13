#include "pch.h"
#include "Constants.h"

// 각 프로토콜별 기본 포트 맵
std::map<std::tstring, WORD> g_DefaultPort =
{
    // Web & File Transfer
    {TEXT("ftp"), 21},
    {TEXT("ftps"), 990},
    {TEXT("http"), 80},
    {TEXT("https"), 443},
    {TEXT("scp"), 22},
    {TEXT("sftp"), 22},
    {TEXT("tftp"), 69},
    {TEXT("dav"), 80},     // WebDAV
    {TEXT("davs"), 443},   // WebDAV Secure

    // Remote Administration & Shell
    {TEXT("rdp"), 3389},
    {TEXT("rlogin"), 513},
    {TEXT("rsh"), 514},
    {TEXT("ssh"), 22},
    {TEXT("telnet"), 23},
    {TEXT("vnc"), 5900},
    {TEXT("winrm"), 5985}, // Windows Remote Management

    // Email
    {TEXT("imap"), 143},
    {TEXT("imaps"), 993},
    {TEXT("pop3"), 110},
    {TEXT("pop3s"), 995},
    {TEXT("smtp"), 25},
    {TEXT("smtps"), 465},
    {TEXT("submission"), 587},

    // Database
    {TEXT("mssql"), 1433},
    {TEXT("mysql"), 3306},
    {TEXT("mongodb"), 27017},
    {TEXT("oracle-sqlnet"), 1521},
    {TEXT("postgresql"), 5432},
    {TEXT("redis"), 6379},

    // Directory & Authentication Services
    {TEXT("kerberos"), 88},
    {TEXT("ldap"), 389},
    {TEXT("ldaps"), 636},
    {TEXT("radius"), 1812},

    // Messaging, Streaming & Other Protocols
    {TEXT("amqp"), 5672},    // Advanced Message Queuing Protocol
    {TEXT("amqps"), 5671},
    {TEXT("dns"), 53},
    {TEXT("git"), 9418},
    {TEXT("irc"), 6667},
    {TEXT("kafka"), 9092},
    {TEXT("mqtt"), 1883},
    {TEXT("ntp"), 123},
    {TEXT("rtsp"), 554},     // Real Time Streaming Protocol
    {TEXT("smb"), 445},
    {TEXT("snmp"), 161},
    {TEXT("sip"), 5060},     // Session Initiation Protocol
    {TEXT("sips"), 5061},
    {TEXT("syslog"), 514},
    {TEXT("ws"), 80},        // WebSocket
    {TEXT("wss"), 443},      // WebSocket Secure
    {TEXT("xmpp-client"), 5222},

    // Common Alternative Ports
    {TEXT("http-alt"), 8080},
    {TEXT("https-alt"), 8443}
};

const std::unordered_map<std::tstring, std::tstring> g_CdnList =
{
    // ==================== 글로벌 Top-Tier CDN ==================== //
    {TEXT(".cloudfront.net"), TEXT("Amazon CloudFront")},
    {TEXT(".awsglobalaccelerator.com"), TEXT("AWS Global Accelerator")},
    {TEXT(".cloudflare.net"), TEXT("Cloudflare CDN")},
    {TEXT(".cloudflare-dns.com"), TEXT("Cloudflare DNS")},
    {TEXT(".workers.dev"), TEXT("Cloudflare Workers")},
    {TEXT(".pages.dev"), TEXT("Cloudflare Pages")},
    {TEXT(".azureedge.net"), TEXT("Azure CDN")},
    {TEXT(".azurefd.net"), TEXT("Azure Front Door")},
    {TEXT(".akamaized.net"), TEXT("Akamai")},
    {TEXT(".akamaihd.net"), TEXT("Akamai HD")},
    {TEXT(".akamaitechnologies.com"), TEXT("Akamai Technologies")},
    {TEXT(".fastly.net"), TEXT("Fastly")},
    {TEXT(".fastlylb.net"), TEXT("Fastly Load Balancer")},
    {TEXT(".llnwd.net"), TEXT("Limelight Networks")},
    {TEXT(".edgecastcdn.net"), TEXT("Edgecast (Edgio)")},
    {TEXT(".incapdns.net"), TEXT("Imperva")},
    {TEXT(".stackpathcdn.com"), TEXT("StackPath")},
    {TEXT(".kxcdn.com"), TEXT("KeyCDN")},
    {TEXT(".b-cdn.net"), TEXT("BunnyCDN")},
    {TEXT(".cdn77.org"), TEXT("CDN77")},
    {TEXT(".cachefly.net"), TEXT("CacheFly")},
    {TEXT(".cdngc.net"), TEXT("CDNetworks")},
    {TEXT(".gslb.taobao.com"), TEXT("Alibaba Cloud CDN")},
    {TEXT(".gcdn.co"), TEXT("Google Cloud CDN")},

    // ==================== 클라우드 스토리지 ==================== //
    {TEXT(".s3.amazonaws.com"), TEXT("Amazon S3")},
    {TEXT(".s3-website"), TEXT("Amazon S3 Static Website")},
    {TEXT(".awsstatic.com"), TEXT("AWS Static Resources")},
    {TEXT(".amazonaws.com"), TEXT("AWS Services (General)")},
    {TEXT(".blob.core.windows.net"), TEXT("Azure Blob Storage")},
    {TEXT(".file.core.windows.net"), TEXT("Azure File Storage")},
    {TEXT(".storage.googleapis.com"), TEXT("Google Cloud Storage")},
    {TEXT(".storage.cloud.google.com"), TEXT("Google Cloud Storage (Alt)")},
    {TEXT(".appspot.com"), TEXT("Google App Engine")},
    {TEXT(".firebaseapp.com"), TEXT("Google Firebase Hosting")},
    {TEXT(".googleusercontent.com"), TEXT("Google Hosted Content")},
    {TEXT(".digitaloceanspaces.com"), TEXT("DigitalOcean Spaces")},
    {TEXT(".linodeobjects.com"), TEXT("Linode Object Storage")},
    {TEXT(".backblazeb2.com"), TEXT("Backblaze B2")},
    {TEXT(".wasabisys.com"), TEXT("Wasabi Hot Cloud Storage")},

    // ==================== 엣지/서버리스 및 기타 ==================== //
    {TEXT(".netlify.app"), TEXT("Netlify")},
    {TEXT(".vercel.app"), TEXT("Vercel")},
    {TEXT(".render.com"), TEXT("Render")},
    {TEXT(".surge.sh"), TEXT("Surge")},
    {TEXT(".cloudfunctions.net"), TEXT("Google Cloud Functions")},
    {TEXT(".appsync-api"), TEXT("AWS AppSync")},
    {TEXT(".cdn.digitaloceanspaces.com"), TEXT("DigitalOcean CDN")},
    {TEXT(".r2.cloudflarestorage.com"), TEXT("Cloudflare R2")}
};

// ==================== URL 단축 서비스 목록 ==================== //
const std::unordered_set<std::tstring> g_ShortUrlList =
{
    TEXT("bit.ly"), TEXT("tinyurl.com"), TEXT("goo.gl"), TEXT("ow.ly"), TEXT("t.co"),
    TEXT("is.gd"), TEXT("buff.ly"), TEXT("adf.ly"), TEXT("bit.do"), TEXT("mcaf.ee"), TEXT("su.pr"),
    TEXT("short.link"), TEXT("clck.ru"), TEXT("cutt.ly"), TEXT("rebrand.ly"), TEXT("linktr.ee"),
    TEXT("bl.ink"), TEXT("lnkd.in"), TEXT("s.id"), TEXT("tiny.cc"), TEXT("rb.gy"), TEXT("v.gd"),
    TEXT("shorturl.at"), TEXT("1url.com"), TEXT("2.gp"), TEXT("x.co"), TEXT("prettylinkpro.com"),

    // 지역별 서비스
    TEXT("han.gl"), TEXT("me2.do"), TEXT("me2.kr"), TEXT("ur.ly"), TEXT("u.nu"), TEXT("kl.am"), TEXT("j.mp"),
    TEXT("po.st"), TEXT("scrnch.me"), TEXT("fifo.cc"), TEXT("tr.im"),

    // 소셜미디어 통합
    TEXT("soo.gd"), TEXT("budurl.com"), TEXT("snip.ly"), TEXT("ity.im"), TEXT("cli.gs"),

    // QR 코드
    TEXT("qr.net"), TEXT("qr.ae"), TEXT("qr-code.link"),

    // 비즈니스/마케팅
    TEXT("sniply.io"), TEXT("hyperurl.co"), TEXT("smarturl.it"), TEXT("ouo.io"), TEXT("ouo.press"),

    // 익명
    TEXT("anonymiz.com"), TEXT("anon.to"), TEXT("anon.ws"), TEXT("hide.me/go"),
    TEXT("t.ly"), TEXT("tny.im"), TEXT("u.to"), TEXT("chilp.it"), TEXT("bc.vc"),

    // 추적/분석 통합
    TEXT("clickmeter.com"), TEXT("snip.li"), TEXT("snipr.com"), TEXT("fur.ly"),

    // 추가 악용 빈번 서비스
    TEXT("shortcm.li"), TEXT("zws.im"), TEXT("goo.su"), TEXT("qps.ru"), TEXT("u.bb"),
    TEXT("tiny.one"), TEXT("gg.gg"), TEXT("dub.sh"), TEXT("dub.co"), TEXT("s2r.co"),
    TEXT("shorter.me"), TEXT("miniurl.be"), TEXT("tinu.be"), TEXT("vztc.com"),

    // 최신 서비스
    TEXT("spoo.me"), TEXT("clck.ru"), TEXT("vo.la"), TEXT("fox.ly"), TEXT("lstu.fr"),
    TEXT("kurzelinks.de"), TEXT("t2m.io"), TEXT("shrtco.de"), TEXT("shrt.li"), TEXT("1link.in"),
    TEXT("hyperlink.ly"), TEXT("urlz.fr"), TEXT("2tu.us"), TEXT("turl.ca"), TEXT("gurl.ly"),
    TEXT("url.ie"), TEXT("sl.co"), TEXT("shorturl.com"), TEXT("lihi.cc"), TEXT("lihi1.cc"),
    TEXT("reurl.cc"), TEXT("pse.is"), TEXT("mee.nu"), TEXT("zee.gl"), TEXT("0rz.tw"),
    TEXT("urlzs.com"), TEXT("url.pm"), TEXT("free.fr"), TEXT("azc.cc"), TEXT("tk.gg"),
    TEXT("cutit.org"), TEXT("shink.in"), TEXT("exe.io"), TEXT("linkvertise.com"),
    TEXT("bc.vc"), TEXT("adfly.com"), TEXT("link1s.com"), TEXT("ouo.press")

    // 한국 서비스
    TEXT("han.gl"), TEXT("me2.do"), TEXT("vo.la"), TEXT("gplinks.in"),
    TEXT("han.gl"), TEXT("bitly.kr"), TEXT("shorturl.kr"),
};

// ==================== URL 단축 서비스 목록 ==================== //
const std::unordered_set<std::tstring> g_SuspiciousTldList =
{
    // 자주 악성으로 보이는 TLD
    TEXT("xyz"), TEXT("top"), TEXT("club"), TEXT("loan"), TEXT("work"), TEXT("monster"), TEXT("pw"), TEXT("icu"), TEXT("cyou"),
    TEXT("buzz"), TEXT("gq"), TEXT("cf"), TEXT("ga"), TEXT("ml"), TEXT("tk"), TEXT("uno"), TEXT("sbs"), TEXT("cn"), TEXT("ru"), TEXT("shop"),
    TEXT("zip"), TEXT("mov"),

    // 무료/저가 TLD
    TEXT("free"), TEXT("ooo"), TEXT("bar"), TEXT("rest"), TEXT("cam"), TEXT("pics"), TEXT("mom"), TEXT("lol"),
    TEXT("rocks"), TEXT("ninja"), TEXT("party"), TEXT("trade"), TEXT("date"), TEXT("racing"), TEXT("accountant"),
    TEXT("science"), TEXT("gdn"), TEXT("men"), TEXT("faith"), TEXT("download"), TEXT("webcam"),

    // 새로운 TLD
    TEXT("bond"), TEXT("country"), TEXT("stream"), TEXT("download"), TEXT("security"), TEXT("mobile"),
    TEXT("hair"), TEXT("christmas"), TEXT("review"), TEXT("space"), TEXT("website"), TEXT("site"), TEXT("online"),
    TEXT("tech"), TEXT("store"), TEXT("fun"), TEXT("tokyo"), TEXT("win"), TEXT("bid"), TEXT("link"), TEXT("click"),
    TEXT("app"), TEXT("dev"), TEXT("page"), TEXT("day"), TEXT("new"), TEXT("now"), TEXT("how"), TEXT("vip"),
    TEXT("biz"), TEXT("info"), TEXT("pro"), TEXT("name"), TEXT("mobi"),
    TEXT("live"), TEXT("life"), TEXT("guru"), TEXT("today"), TEXT("news"), TEXT("support"), TEXT("help"),
    TEXT("world"), TEXT("network"), TEXT("systems"), TEXT("services"), TEXT("solutions"),
    TEXT("beauty"), TEXT("sexy"), TEXT("sex"), TEXT("adult"), TEXT("porn"), TEXT("xxx"), TEXT("dating"), TEXT("singles"),
    TEXT("casino"), TEXT("bet"), TEXT("poker"), TEXT("gambling"), TEXT("games"), TEXT("slots"),
    TEXT("cheap"), TEXT("sale"), TEXT("discount"), TEXT("bargain"), TEXT("promo"), TEXT("deal"),
    TEXT("cloud"), TEXT("host"), TEXT("server"), TEXT("vpn"), TEXT("proxy"),
    TEXT("app"), TEXT("download"), TEXT("software"), TEXT("tools"), TEXT("file"),
    TEXT("press"), TEXT("media"), TEXT("blog"), TEXT("journal"),
    TEXT("health"), TEXT("care"), TEXT("doctor"), TEXT("pharmacy"), TEXT("meds"), TEXT("pills"),
    TEXT("loan"), TEXT("loans"), TEXT("credit"), TEXT("debt"), TEXT("mortgage"),
    TEXT("insurance"), TEXT("lawyer"), TEXT("legal"), TEXT("law"),
    TEXT("study"), TEXT("degree"), TEXT("education"), TEXT("school"), TEXT("university"),

    // 자주 악용되는 국가 tld
    TEXT("tk"), TEXT("ml"), TEXT("ga"), TEXT("cf"), TEXT("gq"),                       // 무료 TLD
    TEXT("ru"), TEXT("cn"), TEXT("in"), TEXT("br"), TEXT("ly"), TEXT("ph"), TEXT("nf"), TEXT("su"),     // 규제 약한 국가
    TEXT("pw"), TEXT("vu"), TEXT("ws"), TEXT("ms"), TEXT("gs"), TEXT("cx"), TEXT("sx"), TEXT("ax"),
    TEXT("bz"), TEXT("ag"), TEXT("sc"), TEXT("mn"), TEXT("la"), TEXT("cd"), TEXT("dj"), TEXT("st")

    // 암호화폐 관련 악용
    TEXT("crypto"), TEXT("nft"), TEXT("blockchain"), TEXT("finance"), TEXT("money"), TEXT("cash"), TEXT("pay"),


    // 피싱, 스팸에서 자주 식별
    TEXT("gives"), TEXT("phone"), TEXT("email"), TEXT("chat"), TEXT("webcam"), TEXT("cam"),
    TEXT("center"), TEXT("centre"), TEXT("agency"), TEXT("company"), TEXT("corporation"),
    TEXT("group"), TEXT("holdings"), TEXT("ventures"), TEXT("capital"), TEXT("partners"),
    TEXT("global"), TEXT("international"), TEXT("world"), TEXT("earth"), TEXT("digital"),
    TEXT("social"), TEXT("community"), TEXT("forum"), TEXT("club"), TEXT("group"),
};

// ==================== 의심스러운 TLD 중 신뢰하는 항목 ==================== //
const std::unordered_set<std::tstring> g_TrustedTldList =
{
    TEXT("velog.io"),
    TEXT("github.io"),
    TEXT("notion.so"),
    TEXT("vercel.app"),
    TEXT("vercel.com")
};

// ==================== 의심스러운 path 항목 ==================== //
const std::unordered_set<std::tstring> g_SuspiciousPathList =
{
    // 계정 정보 관련
    TEXT("reset-password"), TEXT("resetpassword"), TEXT("change-password"),
    TEXT("credential"), TEXT("credentials"),
    TEXT("recovery"), TEXT("recover"), TEXT("restore"), TEXT("unlock"), TEXT("reactivate"),
    TEXT("mfa"), TEXT("2fa"), TEXT("otp"), TEXT("twofa"), TEXT("two-factor"), TEXT("multi-factor"),

    // 흔치 않은 파일/다운로드 관련
    TEXT("crack"), TEXT("cracked"), TEXT("keygen"), TEXT("serial"), TEXT("activator"), TEXT("activation"),
    TEXT("nulled"), TEXT("warez"), TEXT("torrent"), TEXT("magnet"),

    // 긴급/보안 위장 관련
    TEXT("vulnerability"), TEXT("vulnerable"), TEXT("exploit"), TEXT("breach"), TEXT("hacked"),
    TEXT("fraud"), TEXT("scam"),
    TEXT("compromised"), TEXT("compromise"), TEXT("infected"), TEXT("infection"),
    TEXT("urgent"), TEXT("immediate"), TEXT("action-required"), TEXT("action_required"), TEXT("required-action"),

    // 금융 관련
    TEXT("invoice-overdue"), TEXT("invoice-pending"), TEXT("payment-overdue"),
    TEXT("wire"), TEXT("wiretransfer"),
    TEXT("wallet"), TEXT("crypto-wallet"), TEXT("cryptowallet"),

    // 소셜 엔지니어링/미끼
    TEXT("winner"), TEXT("winners"), TEXT("won"), TEXT("lottery"), TEXT("sweepstakes"),
    TEXT("claim-airdrop"), TEXT("claim-reward"), TEXT("claim-token"),

    // 암호화폐/NFT/Web3
    TEXT("metamask"), TEXT("trust-wallet"), TEXT("trustwallet"),
    TEXT("connect-wallet"), TEXT("connectwallet"), TEXT("sign-transaction"),
    TEXT("seed-phrase"), TEXT("recovery-phrase"), TEXT("private-key"), TEXT("mnemonic"),

    // 클라우드/SaaS
    TEXT("admin"), TEXT("administrator"), TEXT("console"),
    TEXT("webhook"), TEXT("callback"),

    // 악성 행위 지표
    TEXT("shell"), TEXT("cmd"), TEXT("exec"), TEXT("execute"), TEXT("exploit"),
    TEXT("backdoor"), TEXT("reverse-shell"), TEXT("bind-shell"), TEXT("webshell"),
    TEXT("uploader"), TEXT("filemanager"), TEXT("file-manager"),
    TEXT("eval"), TEXT("base64"), TEXT("decode"), TEXT("decrypt"), TEXT("obfuscate"),

    // AI/ML 서비스 관련
    TEXT("api-key"),

    // Web3/블록체인 추가 키워드
    TEXT("free-token"), TEXT("bonus-token"),

    // 피싱 공격 최신 트렌드
    TEXT("account-suspended"), TEXT("account-locked"), TEXT("account-disabled"),
    TEXT("unusual-activity"), TEXT("unusual-login"), TEXT("unrecognized-device"),
    TEXT("identity-verification"), TEXT("verify-identity"), TEXT("verify-now"),
    TEXT("tax-refund"), TEXT("irs-refund"),
    TEXT("prize-claim"), TEXT("lottery-winner"), TEXT("inheritance"), TEXT("beneficiary"),
    TEXT("court-notice"), TEXT("legal-notice"), TEXT("subpoena"), TEXT("warrant"),

    // -------------------- 비즈니스 이메일 침해 (BEC) 관련 -------------------- //
    TEXT("ceo-urgent"), TEXT("cfo-request"), TEXT("wire-transfer-urgent"), TEXT("payment-urgent"),
    TEXT("vendor-update"), TEXT("banking-update"), TEXT("account-update-required"),

    // -------------------- 랜섬웨어/악성코드 관련 -------------------- //
    TEXT("decrypt-files"), TEXT("recovery-key"), TEXT("decryption-key"), TEXT("ransom"),
    TEXT("bitcoin-payment"), TEXT("crypto-payment"), TEXT("payment-deadline"),
    TEXT("files-encrypted"), TEXT("data-locked"), TEXT("restore-access"),

    // -------------------- 최신 소셜 엔지니어링 -------------------- //
    TEXT("act-now"), TEXT("expires-soon"), TEXT("last-chance"),
    TEXT("verify-email-now"), TEXT("confirm-email-now"),
    TEXT("security-alert"), TEXT("security-warning"), TEXT("breach-notification"),
    TEXT("data-breach"), TEXT("password-reset-required"), TEXT("change-password-now"),
    TEXT("unauthorized-access"), TEXT("suspicious-login"),

    // -------------------- 클라우드/DevOps 공격 -------------------- //
    TEXT("gitlab-token"), TEXT("github-token"),
    TEXT("secrets"), TEXT("credentials-manager"), TEXT("vault"), TEXT("key-vault"),

    // -------------------- 모바일 앱 관련 -------------------- //
    TEXT("apk-download"),
};

const std::unordered_set<std::tstring> g_DocExt =
{
    TEXT("pdf"), TEXT("rtf"), TEXT("one"),
    TEXT("hwp"), TEXT("hwpx"),
    TEXT("doc"), TEXT("docx"), TEXT("docm"), TEXT("dotm"),
    TEXT("ppt"), TEXT("pptx"), TEXT("pptm"), TEXT("potm"), TEXT("ppam"),
    TEXT("xls"), TEXT("xlsx"), TEXT("xlsm"), TEXT("xotm"),
};

// ==================== 실행 파일 확장자 목록 ==================== //
const std::unordered_set<std::tstring> g_ExcutableList =
{
    // Windows 실행 파일
    TEXT("exe"), TEXT("dll"), TEXT("scr"), TEXT("com"), TEXT("pif"), TEXT("msi"), TEXT("msp"), TEXT("cpl"), TEXT("ocx"),
    TEXT("ax"), TEXT("sys"), TEXT("drv"),                                             // 드라이버

    // Windows 스크립트 및 바로가기
    TEXT("bat"), TEXT("cmd"), TEXT("vbs"), TEXT("vbe"), TEXT("js"), TEXT("jse"), TEXT("ps1"), TEXT("psm1"),        // PowerShell 모듈
    TEXT("wsf"), TEXT("wsh"), TEXT("hta"), TEXT("lnk"), TEXT("url"), TEXT("inf"), TEXT("reg"),               // 레지스트리

    // macOS 실행 파일 및 패키지
    TEXT("app"), TEXT("dmg"), TEXT("pkg"), TEXT("mpkg"), TEXT("command"), TEXT("action"), TEXT("workflow"),
    TEXT("macho"), TEXT("dylib"), TEXT("bundle"), TEXT("kext"),

    // Linux 및 크로스플랫폼
    TEXT("sh"), TEXT("bash"), TEXT("zsh"), TEXT("fish"), TEXT("ksh"), TEXT("csh"),                     // 셸 스크립트
    TEXT("run"), TEXT("bin"), TEXT("elf"), TEXT("out"),                                    // 바이너리
    TEXT("py"), TEXT("pyc"), TEXT("pyo"), TEXT("pyw"), TEXT("pyz"),                              // Python
    TEXT("pl"), TEXT("pm"), TEXT("t"), TEXT("pod"),                                        // Perl
    TEXT("rb"), TEXT("rbw"),                                                   // Ruby
    TEXT("jar"), TEXT("war"), TEXT("ear"), TEXT("jad"),                                    // Java
    TEXT("deb"), TEXT("rpm"), TEXT("snap"), TEXT("flatpak"), TEXT("AppImage"),

    //// 압축 파일
    //TEXT("zip"), TEXT("rar"), TEXT("7z"), TEXT("tar"), TEXT("gz"), TEXT("bz2"), TEXT("xz"), TEXT("tgz"), TEXT("tbz2"),
    //TEXT("cab"), TEXT("arj"), TEXT("lzh"), TEXT("ace"), TEXT("zoo"), TEXT("arc"), TEXT("pak"), TEXT("sit"), TEXT("sitx"),
    //TEXT("zipx"), TEXT("s7z"), TEXT("wim"), TEXT("swm"),

    //// 디스크 이미지
    //TEXT("iso"), TEXT("img"), TEXT("bin"), TEXT("nrg"), TEXT("mdf"), TEXT("mds"), TEXT("toast"),
    //TEXT("vhd"), TEXT("vhdx"), TEXT("vmdk"), TEXT("vdi"), TEXT("qcow"), TEXT("qcow2"),                 // 가상 디스크

    // 모바일
    TEXT("apk"), TEXT("ipa"), TEXT("xap"), TEXT("appx"), TEXT("aab"),                            // Android, iOS, Windows Phone

    //// 컨테이너/가상화
    //TEXT("ova"), TEXT("ovf"), TEXT("docker"), TEXT("dockerfile"),

    // 스크립트 언어
    TEXT("lua"), TEXT("tcl"), TEXT("awk"), TEXT("sed"),
    TEXT("r"), TEXT("jl"),                                                     // R, Julia

    //// 데이터베이스/설정
    //TEXT("sql"), TEXT("db"), TEXT("sqlite"), TEXT("mdb"), TEXT("accdb"),
    //TEXT("xml"), TEXT("config"), TEXT("conf"), TEXT("ini"), TEXT("plist"),                       // 설정 파일

    // 기타 실행 가능
    TEXT("gadget"), TEXT("msi"), TEXT("msu"), TEXT("mst"),                                 // Windows 업데이트/가젯
    TEXT("application"), TEXT("air"),                                          // Adobe AIR
    TEXT("action"), TEXT("workflow"),                                          // Automator
    TEXT("scpt"), TEXT("scptd"), TEXT("applescript")                                 // AppleScript
};

// ==================== 매크로 포함 문서 ==================== //
const std::unordered_set<std::tstring> g_MacroDocList =
{
    TEXT("docm"), TEXT("xlsm"), TEXT("pptm"), TEXT("dotm"), TEXT("xltm"), TEXT("potm"), TEXT("ppsm"), TEXT("sldm"),
    TEXT("rtf"), TEXT("one"), TEXT("pub"), TEXT("vsd"),                                    // RTF, OneNote, Publisher, Visio
    TEXT("odt"), TEXT("ods"), TEXT("odp"), TEXT("odg"),                                    // OpenDocument (매크로 가능)
};

const std::vector<std::tstring> g_WebVulnList =
{
    // XSS (Cross-Site Scripting)
    TEXT("<script>"), TEXT("</script>"), TEXT("<script"), TEXT("script>"),
    TEXT("onerror="), TEXT("onload="), TEXT("onmouseover="), TEXT("onclick="), TEXT("onfocus="), TEXT("onblur="),
    TEXT("onabort="), TEXT("onchange="), TEXT("ondblclick="), TEXT("onkeydown="), TEXT("onkeypress="), TEXT("onkeyup="),
    TEXT("onmousedown="), TEXT("onmousemove="), TEXT("onmouseout="), TEXT("onmouseup="), TEXT("onresize="),
    TEXT("onscroll="), TEXT("onselect="), TEXT("onsubmit="), TEXT("onunload="),
    TEXT("javascript:"), TEXT("vbscript:"), TEXT("data:text/html"),
    TEXT("alert("), TEXT("prompt("), TEXT("confirm("), TEXT("document.cookie"), TEXT("document.write("),
    TEXT("String.fromCharCode("), TEXT("eval("), TEXT("unescape("), TEXT("window.location"),
    TEXT("<img>"), TEXT("<img "), TEXT("src="), TEXT("<iframe>"), TEXT("<iframe "), TEXT("<svg>"), TEXT("<svg "),
    TEXT("<body>"), TEXT("<body "), TEXT("<video>"), TEXT("<audio>"), TEXT("<embed>"), TEXT("<object>"),
    TEXT("<input"), TEXT("<form"), TEXT("<link"), TEXT("<meta"), TEXT("<style>"), TEXT("<base"),
    TEXT("expression("), TEXT("import("), TEXT("&#"), TEXT("\\x"), TEXT("\\u"),                  // 인코딩 우회

    // SQL Injection
    TEXT("' or '"), TEXT("'or'"), TEXT("' or 1=1"), TEXT("' or '1'='1"), TEXT("' or true--"),
    TEXT("' and '"), TEXT("'and'"), TEXT("' and 1=1"),
    TEXT("\" or \""), TEXT("\"or\""), TEXT("\" or 1=1"),
    TEXT("--"), TEXT("/*"), TEXT("*/"), TEXT("#"), TEXT(";--"), TEXT(");--"), TEXT("';--"),
    TEXT("union select"), TEXT("union all select"), TEXT("union distinct"),
    TEXT("select from"), TEXT("select * from"), TEXT("select top"),
    TEXT("insert into"), TEXT("update set"), TEXT("delete from"), TEXT("drop table"), TEXT("drop database"),
    TEXT("truncate table"), TEXT("alter table"), TEXT("create table"),
    TEXT("exec("), TEXT("execute("), TEXT("xp_cmdshell"), TEXT("sp_executesql"), TEXT("sp_configure"),
    TEXT("information_schema"), TEXT("sysobjects"), TEXT("syscolumns"),
    TEXT("waitfor delay"), TEXT("benchmark("), TEXT("pg_sleep("), TEXT("sleep("), TEXT("dbms_pipe"),  // Time-based
    TEXT("extractvalue("), TEXT("updatexml("), TEXT("exp("), TEXT("pow("),                      // Error-based
    TEXT("concat("), TEXT("group_concat("), TEXT("string_agg("),                          // Data exfiltration
    TEXT("into outfile"), TEXT("into dumpfile"), TEXT("load_file("),                      // File operations
    TEXT("0x"), TEXT("char("), TEXT("chr("), TEXT("ascii("), TEXT("substring("),                      // Encoding/Functions

    // Command Injection
    TEXT("|cat"), TEXT("|ls"), TEXT("|dir"), TEXT("|pwd"), TEXT("|whoami"), TEXT("|id"), TEXT("|uname"),
    TEXT("&cat"), TEXT("&ls"), TEXT("&dir"), TEXT("&pwd"), TEXT("&whoami"), TEXT("&id"), TEXT("&uname"),
    TEXT(";cat"), TEXT(";ls"), TEXT(";dir"), TEXT(";pwd"), TEXT(";whoami"), TEXT(";id"), TEXT(";uname"),
    TEXT("&&"), TEXT("||"), TEXT("`"), TEXT("$("), TEXT("${"),                                       // Sub-shell
    TEXT("|wget"), TEXT("|curl"), TEXT("|nc"), TEXT("|netcat"), TEXT("|bash"), TEXT("|sh"), TEXT("|python"),
    TEXT("&wget"), TEXT("&curl"), TEXT("&nc"), TEXT("&bash"), TEXT("&python"),
    TEXT(";wget"), TEXT(";curl"), TEXT(";nc"), TEXT(";bash"), TEXT(";python"),
    TEXT("etc/passwd"), TEXT("etc/shadow"), TEXT("/etc/hosts"), TEXT("boot.ini"), TEXT("win.ini"),
    TEXT("net user"), TEXT("net localgroup"), TEXT("cmd.exe"), TEXT("powershell"),
    TEXT("/bin/bash"), TEXT("/bin/sh"), TEXT("/usr/bin"),

    // Path Traversal / LFI
    TEXT("../"), TEXT("..\\"), TEXT("..%2f"), TEXT("..%5c"), TEXT("..%252f"),                        // URL 인코딩
    TEXT(".%2e/"), TEXT(".%2e\\"), TEXT("%2e%2e/"), TEXT("%2e%2e\\"),
    TEXT("....//"), TEXT("....\\\\"),
    TEXT("/etc/passwd"), TEXT("/etc/shadow"), TEXT("/proc/self/environ"),
    TEXT("c:\\windows"), TEXT("c:\\winnt"), TEXT("/windows/"), TEXT("/winnt/"),
    TEXT("WEB-INF"), TEXT("META-INF"), TEXT("web.xml"), TEXT("web.config"),
    TEXT("htaccess"), TEXT(".htpasswd"), TEXT(".bashrc"), TEXT(".bash_history"),
    TEXT("/var/www"), TEXT("/var/log"), TEXT("application.properties"),

    // XXE (XML External Entity)
    TEXT("<!DOCTYPE"), TEXT("<!ENTITY"), TEXT("SYSTEM"), TEXT("PUBLIC"),
    TEXT("file://"), TEXT("http://"), TEXT("ftp://"), TEXT("expect://"), TEXT("php://"),

    // SSRF (Server-Side Request Forgery)
    TEXT("localhost"), TEXT("127.0.0.1"), TEXT("0.0.0.0"), TEXT("[::]"), TEXT("0177.0.0.1"),        // 로컬 주소
    TEXT("169.254.169.254"),                                                 // AWS 메타데이터
    TEXT("metadata.google.internal"),                                        // GCP 메타데이터
    TEXT("file://"), TEXT("dict://"), TEXT("gopher://"), TEXT("tftp://"),

    // NoSQL Injection
    TEXT("$ne"), TEXT("$eq"), TEXT("$gt"), TEXT("$gte"), TEXT("$lt"), TEXT("$lte"), TEXT("$in"), TEXT("$nin"),       // MongoDB
    TEXT("$where"), TEXT("$regex"), TEXT("$exists"), TEXT("$type"), TEXT("$mod"),
    TEXT("||"), TEXT("&&"), TEXT("true"), TEXT("false"), TEXT("null"),

    // LDAP Injection
    TEXT("*)(uid=*"), TEXT("*)(objectClass=*"), TEXT("*()|"), TEXT("*))%00"),
    TEXT("admin*"), TEXT("*,dc="), TEXT("cn="), TEXT("ou="),

    // Template Injection
    TEXT("{{"), TEXT("}}"), TEXT("${"), TEXT("<%"), TEXT("%>"), TEXT("<#"), TEXT("#>"),
    TEXT("#{"), TEXT("@{"), TEXT("[["), TEXT("]]"),
    TEXT("__import__"), TEXT("eval"), TEXT("exec"), TEXT("compile"),

    // Header Injection
    TEXT("\\r\\n"), TEXT("%0d%0a"), TEXT("\\n"), TEXT("\\r"), TEXT("\n"), TEXT("\r"),
    TEXT("Content-Type:"), TEXT("Location:"), TEXT("Set-Cookie:"),

    // Open Redirect
    TEXT("//"), TEXT("http://"), TEXT("https://"), TEXT("javascript:"), TEXT("data:"),
    TEXT("\\/\\/"), TEXT("%2f%2f"), TEXT("@"),

    // Deserialization
    TEXT("rO0"), TEXT("aced0005"),                                                 // Java serialization
    TEXT("__reduce__"), TEXT("__setstate__"), TEXT("pickle"), TEXT("cPickle"),                // Python
    TEXT("unserialize("), TEXT("O:"),                                             // PHP

    // 기타 공격 패턴 
    TEXT("phpinfo("), TEXT("system("), TEXT("passthru("), TEXT("shell_exec("), TEXT("popen("),      // PHP
    TEXT("base64_decode("), TEXT("gzinflate("), TEXT("str_rot13("),
    TEXT("assert("), TEXT("create_function("), TEXT("preg_replace("),
    TEXT("/e"),                                                             // preg_replace /e modifier

    // Server-Side Template Injection (SSTI)
    TEXT("{{config"), TEXT("{{self"), TEXT("{{request"), TEXT("{{lipsum"), TEXT("{{cycler"),
    TEXT("{{joiner"), TEXT("{{namespace"), TEXT("__class__"), TEXT("__bases__"), TEXT("__subclasses__"),
    TEXT("__import__"), TEXT("__builtins__"), TEXT("__globals__"), TEXT("__init__"),
    TEXT("config.items"), TEXT("settings.SECRET_KEY"), TEXT("self.__dict__"),
    TEXT("${{"), TEXT("*{"), TEXT("{% "), TEXT("%}"), TEXT("{%"), TEXT("freemarker"), TEXT("velocity"),
    TEXT("thymeleaf"), TEXT("pebble"), TEXT("jinja"), TEXT("twig"), TEXT("smarty"),

    // Log4Shell / Log Injection
    TEXT("${jndi:"), TEXT("${jndi:ldap:"), TEXT("${jndi:rmi:"), TEXT("${jndi:dns:"),
    TEXT("${jndi:ldaps:"), TEXT("${jndi:iiop:"), TEXT("${jndi:corba:"),
    TEXT("${env:"), TEXT("${sys:"), TEXT("${java:"), TEXT("${lower:"), TEXT("${upper:"),
    TEXT("${date:"), TEXT("${ctx:"), TEXT("${main:"), TEXT("${spring:"),

    // GraphQL Injection
    TEXT("mutation{"), TEXT("query{"), TEXT("subscription{"), TEXT("__schema"), TEXT("__type"),
    TEXT("introspection"), TEXT("fragment"), TEXT("...on"), TEXT("@skip"), TEXT("@include"),
    TEXT("__typename"), TEXT("edges{"), TEXT("node{"), TEXT("pageInfo"),

    // JWT Attacks
    TEXT("eyJ"), TEXT("eyJhbGciOiJub25lIg"), TEXT("\"alg\":\"none\""), TEXT("\"alg\":\"HS256\""),
    TEXT("jwt_tool"), TEXT("jwt.io"), TEXT("kid"), TEXT("jku"), TEXT("x5u"),

    // CORS Misconfiguration
    TEXT("Access-Control-Allow-Origin: *"), TEXT("Access-Control-Allow-Credentials: true"),
    TEXT("*."), TEXT("null"), TEXT("evil.com"), TEXT("attacker.com"),

    // CRLF Injection 확장
    TEXT("%0d%0a%0d%0a"), TEXT("%0a%0d%0a%0d"), TEXT("\\r\\n\\r\\n"),
    TEXT("\\n\\r\\n\\r"), TEXT("\r\n\r\n"), TEXT("\n\r\n\r"),

    // File Upload Bypass
    TEXT(".php."), TEXT(".php3."), TEXT(".php4."), TEXT(".php5."), TEXT(".phtml."),
    TEXT(".asp."), TEXT(".aspx."), TEXT(".jsp."), TEXT(".jspx."),
    TEXT("shell.php%00.jpg"), TEXT("shell.jpg.php"),
    TEXT(".htaccess"), TEXT("web.config"), TEXT(".user.ini"),
    TEXT("<?php"), TEXT("<%@"), TEXT("<%="), TEXT("<script"), TEXT("<%"),

    // Prototype Pollution
    TEXT("__proto__"), TEXT("constructor.prototype"), TEXT("prototype.constructor"),
    TEXT("constructor[prototype]"), TEXT("__proto__["), TEXT("constructor["),

    // Mass Assignment
    TEXT("is_admin"), TEXT("isAdmin"), TEXT("admin"), TEXT("role"), TEXT("roles"),
    TEXT("is_superuser"), TEXT("permissions"), TEXT("privilege"), TEXT("privileges"),

    // API Abuse
    TEXT("../../../"), TEXT("/.."), TEXT("/%2e%2e/"), TEXT("/..%2f"),
    TEXT("/api/v1/"), TEXT("/api/v2/"), TEXT("/api/internal/"), TEXT("/api/admin/"),
    TEXT("/graphql"), TEXT("/swagger"), TEXT("/api-docs"), TEXT("/openapi"),

    // Cloud Metadata Attacks
    TEXT("169.254.169.254/latest/meta-data"), TEXT("169.254.169.254/latest/user-data"),
    TEXT("metadata.azure.com"), TEXT("metadata.google.internal/computeMetadata"),
    TEXT("100.100.100.200/latest/meta-data"), TEXT("alibaba-metadata"),
    TEXT("digitalocean-metadata"), TEXT("oracle-metadata"),

    // Container Escape
    TEXT("/var/run/docker.sock"), TEXT("/proc/self/cgroup"), TEXT("/proc/self/mountinfo"),
    TEXT("/.dockerenv"), TEXT("/run/secrets"), TEXT("kubectl"), TEXT("crictl"),

    // Race Condition Indicators
    TEXT("TOCTOU"), TEXT("sleep("), TEXT("usleep("), TEXT("time-of-check"),
    TEXT("time-of-use"), TEXT("race-condition"),

    // Business Logic Flaws
    TEXT("quantity=-"), TEXT("price=-"), TEXT("amount=-"), TEXT("discount=100"),
    TEXT("coupon="), TEXT("promo=999"), TEXT("referral=admin"),

    // WebAssembly Attacks
    TEXT(".wasm"), TEXT("WebAssembly"), TEXT("wasm_bindgen"), TEXT("Module.instantiate"),

    // AI/ML Model Attacks
    TEXT("prompt-injection"), TEXT("ignore previous instructions"), TEXT("system:"),
    TEXT("assistant:"), TEXT("user:"), TEXT("###"), TEXT("<|endoftext|>"), TEXT("<|im_start|>"),
    TEXT("jailbreak"), TEXT("DAN mode"), TEXT("developer mode"),

    // Supply Chain Attacks
    TEXT("package.json"), TEXT("node_modules"), TEXT("composer.json"), TEXT("requirements.txt"),
    TEXT("pom.xml"), TEXT("build.gradle"), TEXT("Cargo.toml"), TEXT("go.mod")
};

const std::vector<std::tstring> g_UserDirectoryList =
{
    TEXT("/users/"), TEXT("/user/"), TEXT("/member/"), TEXT("/members/"),
    TEXT("/profile/"), TEXT("/profiles/"), TEXT("/people/"), TEXT("/person/"),
    TEXT("/author/"), TEXT("/authors/"), TEXT("/home/"), TEXT("/~"),
    TEXT("/u/"), TEXT("/account/"), TEXT("/accounts/")
};

const std::unordered_set<std::tstring> g_SensitiveTokenList =
{
    // API 키 관련
    TEXT("apikey"), TEXT("api_key"), TEXT("api-key"), TEXT("key"), TEXT("appkey"), TEXT("app_key"), TEXT("app-key"),
    TEXT("applicationkey"), TEXT("application_key"), TEXT("client_id"), TEXT("clientid"),
    TEXT("consumer_key"), TEXT("consumerkey"),

    // 토큰 관련
    TEXT("token"), TEXT("access_token"), TEXT("accesstoken"), TEXT("access-token"),
    TEXT("auth_token"), TEXT("authtoken"), TEXT("auth-token"), TEXT("bearer"), TEXT("bearer_token"),
    TEXT("refresh_token"), TEXT("refreshtoken"), TEXT("refresh-token"),
    TEXT("jwt"), TEXT("id_token"), TEXT("idtoken"), TEXT("id-token"),
    TEXT("csrf_token"), TEXT("csrftoken"), TEXT("xsrf_token"),

    // 세션 관련
    TEXT("session"), TEXT("sessionid"), TEXT("session_id"), TEXT("session-id"),
    TEXT("sid"), TEXT("phpsessid"), TEXT("jsessionid"), TEXT("aspsessionid"),
    TEXT("connect.sid"), TEXT("laravel_session"),

    // 인증 관련
    TEXT("auth"), TEXT("authorization"), TEXT("authentication"),
    TEXT("credential"), TEXT("credentials"), TEXT("cred"), TEXT("creds"),

    // 비밀 키 관련
    TEXT("secret"), TEXT("secret_key"), TEXT("secretkey"), TEXT("secret-key"),
    TEXT("client_secret"), TEXT("clientsecret"), TEXT("client-secret"),
    TEXT("private_key"), TEXT("privatekey"), TEXT("private-key"),
    TEXT("api_secret"), TEXT("apisecret"), TEXT("api-secret"),
    TEXT("app_secret"), TEXT("appsecret"),
    TEXT("master_key"), TEXT("masterkey"),

    // OAuth 관련
    TEXT("oauth"), TEXT("oauth_token"), TEXT("oauthtoken"), TEXT("oauth-token"),
    TEXT("code"), TEXT("auth_code"), TEXT("authcode"), TEXT("authorization_code"),
    TEXT("grant_type"), TEXT("grant-type"),

    // 클라우드 서비스 키
    // AWS
    TEXT("aws_access_key_id"), TEXT("aws_secret_access_key"), TEXT("aws_session_token"),
    TEXT("amazon_access_key"), TEXT("amazon_secret_key"),
    // Azure
    TEXT("azure_client_id"), TEXT("azure_client_secret"), TEXT("azure_tenant_id"),
    TEXT("azure_subscription_id"),
    // Google Cloud
    TEXT("gcp_api_key"), TEXT("google_api_key"), TEXT("google_application_credentials"),
    TEXT("firebase_token"), TEXT("firebase_api_key"),
    // GitHub
    TEXT("github_token"), TEXT("gh_token"), TEXT("github_pat"), TEXT("github_oauth"),
    // Stripe
    TEXT("stripe_key"), TEXT("stripe_secret"), TEXT("stripe_publishable"),
    // Twilio
    TEXT("twilio_account_sid"), TEXT("twilio_auth_token"),
    // SendGrid
    TEXT("sendgrid_api_key"), TEXT("sendgrid_key"),
    // Slack
    TEXT("slack_token"), TEXT("slack_webhook"), TEXT("slack_api_token"),
    // Mailgun
    TEXT("mailgun_api_key"), TEXT("mailgun_key"),
    // PayPal
    TEXT("paypal_client_id"), TEXT("paypal_secret"),

    // 데이터베이스 관련
    TEXT("db_password"), TEXT("database_password"), TEXT("db_pass"),
    TEXT("mysql_password"), TEXT("postgres_password"), TEXT("mongodb_password"),
    TEXT("redis_password"), TEXT("connection_string"), TEXT("database_url"),

    // 암호화폐 관련
    TEXT("wallet_key"), TEXT("private_key"), TEXT("seed_phrase"), TEXT("mnemonic"),
    TEXT("bitcoin_key"), TEXT("ethereum_key"), TEXT("crypto_key"),

    // 기타
    TEXT("password"), TEXT("passwd"), TEXT("pwd"), TEXT("pass"), TEXT("passphrase"),
    TEXT("signature"), TEXT("sign"), TEXT("verification"), TEXT("verify"),
    TEXT("nonce"), TEXT("salt"), TEXT("hash"), TEXT("hmac"),
    TEXT("encryption_key"), TEXT("decrypt_key"), TEXT("cipher_key")
};

const std::unordered_set<std::tstring> g_AbnormalUriList =
{
    // 스크립트 실행 관련
    TEXT("javascript"), TEXT("data"), TEXT("vbscript"), TEXT("livescript"),

    // 로컬 자원 접근
    TEXT("file"), TEXT("res"), TEXT("resource"), TEXT("mhtml"), TEXT("mk"),
    TEXT("jar"), TEXT("wyciwyg"),

    // 네트워크 프로토콜 (비표준/위험)
    TEXT("ftp"), TEXT("ftps"), TEXT("sftp"), TEXT("tftp"), TEXT("telnet"), TEXT("gopher"), TEXT("dict"),
    TEXT("ldap"), TEXT("ldaps"),

    // WebSocket
    TEXT("ws"), TEXT("wss"),

    // 이메일 및 통신
    TEXT("mailto"), TEXT("news"), TEXT("nntp"), TEXT("irc"), TEXT("ircs"), TEXT("xmpp"),
    TEXT("sip"), TEXT("sips"), TEXT("tel"), TEXT("sms"), TEXT("mms"),

    // 브라우저 내부
    TEXT("about"), TEXT("chrome"), TEXT("edge"), TEXT("safari"), TEXT("opera"), TEXT("firefox"),
    TEXT("moz-extension"), TEXT("chrome-extension"), TEXT("edge-extension"),
    TEXT("browser"), TEXT("view-source"), TEXT("blob"),

    // P2P 및 특수 프로토콜
    TEXT("magnet"), TEXT("torrent"), TEXT("ed2k"), TEXT("bitcoin"), TEXT("ethereum"),
    TEXT("ipfs"), TEXT("ipns"), TEXT("dat"), TEXT("ssb"),

    // 모바일/앱 딥링크
    TEXT("intent"), TEXT("android-app"), TEXT("ios-app"), TEXT("market"), TEXT("itms"),
    TEXT("itms-apps"), TEXT("whatsapp"), TEXT("fb"), TEXT("twitter"), TEXT("instagram"),

    // 스트리밍 프로토콜
    TEXT("rtmp"), TEXT("rtmps"), TEXT("rtsp"), TEXT("rtsps"), TEXT("mms"), TEXT("mmsh"),

    // 개발/디버깅
    TEXT("sourcemap"), TEXT("webpack"), TEXT("webpack-internal"),

    // 기타 위험 프로토콜
    TEXT("callto"), TEXT("skype"), TEXT("zoom"), TEXT("slack"), TEXT("discord"),
    TEXT("steam"), TEXT("git"), TEXT("svn"), TEXT("cvs"),

    // AI/ML 서비스 딥링크
    TEXT("chatgpt"), TEXT("claude-ai"), TEXT("bard"), TEXT("midjourney"),

    // Web3/블록체인
    TEXT("web3"), TEXT("ethereum"), TEXT("metamask"), TEXT("phantom"), TEXT("coinbase"),
    TEXT("walletconnect"), TEXT("trust"), TEXT("crypto"),

    // 소셜미디어 앱 딥링크
    TEXT("tiktok"), TEXT("snapchat"), TEXT("wechat"), TEXT("line"), TEXT("kakao"),
    TEXT("telegram"), TEXT("signal"), TEXT("viber"), TEXT("messenger"),

    // 협업 도구
    TEXT("ms-teams"), TEXT("msteams"), TEXT("notion"), TEXT("obsidian"),
    TEXT("evernote"), TEXT("onenote"), TEXT("trello"), TEXT("asana"),

    // 비즈니스/결제
    TEXT("paypal"), TEXT("venmo"), TEXT("cashapp"), TEXT("gpay"), TEXT("paytm"),

    // 클라우드/파일 공유
    TEXT("dropbox"), TEXT("googledrive"), TEXT("onedrive"), TEXT("box"),
    TEXT("icloud"), TEXT("mega"), TEXT("wetransfer"),

    // 스트리밍/미디어
    TEXT("spotify"), TEXT("applemusic"), TEXT("youtube"), TEXT("netflix"),
    TEXT("twitch"), TEXT("vimeo"), TEXT("soundcloud"),

    // IoT/스마트홈
    TEXT("homekit"), TEXT("alexa"), TEXT("google-home"), TEXT("smartthings"),
    TEXT("ifttt"), TEXT("nest"), TEXT("ring"), TEXT("hue"),

    // AR/VR
    TEXT("oculus"), TEXT("vr"), TEXT("ar"), TEXT("spatial"),

    // 교육
    TEXT("zoom-meeting"), TEXT("teams-meeting"), TEXT("webex-meeting"),
    TEXT("classroom"), TEXT("canvas"), TEXT("blackboard"), TEXT("moodle"),

    // 위치/지도
    TEXT("maps"), TEXT("waze"), TEXT("uber"), TEXT("lyft"), TEXT("grab"),

    // 음성 어시스턴트
    TEXT("siri"), TEXT("bixby"), TEXT("cortana"), TEXT("google-assistant"),

    // 디버깅/개발
    TEXT("adb"), TEXT("debug"), TEXT("devtools"), TEXT("inspector"),
    TEXT("chrome-devtools"), TEXT("edge-devtools"),

    // 레거시/비표준 위험 프로토콜
    TEXT("finger"), TEXT("nntp"), TEXT("rsync"), TEXT("rlogin"),
    TEXT("rsh"), TEXT("rexec"), TEXT("netbios"), TEXT("smb"),

    // 실험적/비표준
    TEXT("gemini"), TEXT("gopher"), TEXT("sparql"), TEXT("xri"),
    TEXT("ni"), TEXT("nih"), TEXT("tag"), TEXT("cap"),

    // 컨테이너/가상화
    TEXT("docker"), TEXT("kubernetes"), TEXT("k8s"), TEXT("podman")
};

const std::unordered_set<std::tstring> g_DangerousParameterList =
{
    // 오픈 리다이렉션 (Open Redirect)
    TEXT("redirect"), TEXT("redir"), TEXT("redirect_uri"), TEXT("redirect_url"), TEXT("redirecturl"), TEXT("redirectUri"),
    TEXT("next"), TEXT("nexturl"), TEXT("next_url"), TEXT("nextUrl"),
    TEXT("continue"), TEXT("continueurl"), TEXT("continue_url"), TEXT("continueUrl"),
    TEXT("return"), TEXT("returnurl"), TEXT("return_url"), TEXT("returnto"), TEXT("return_to"), TEXT("returnUrl"), TEXT("returnTo"),
    TEXT("goto"), TEXT("gotourl"), TEXT("go"), TEXT("goTo"),
    TEXT("destination"), TEXT("dest"), TEXT("target"), TEXT("targetUrl"),
    TEXT("follow"), TEXT("followup"), TEXT("forward"), TEXT("forwardurl"), TEXT("forwardUrl"),
    TEXT("success"), TEXT("success_url"), TEXT("successurl"),
    TEXT("failure"), TEXT("failure_url"), TEXT("failureurl"),
    TEXT("callback_url"), TEXT("callbackurl"), TEXT("callbackUrl"),
    TEXT("landing"), TEXT("landing_page"), TEXT("landingpage"),

    // URL/파일 접근 (SSRF, LFI, RFI)
    TEXT("url"), TEXT("uri"), TEXT("link"), TEXT("href"), TEXT("src"), TEXT("source"),
    TEXT("path"), TEXT("filepath"), TEXT("file_path"), TEXT("filePath"),
    TEXT("file"), TEXT("filename"), TEXT("file_name"), TEXT("fileName"),
    TEXT("document"), TEXT("doc"), TEXT("page"), TEXT("resource"),
    TEXT("to"), TEXT("load"), TEXT("fetch"), TEXT("get"), TEXT("retrieve"),
    TEXT("download"), TEXT("upload"), TEXT("import"), TEXT("export"),
    TEXT("include"), TEXT("require"), TEXT("read"), TEXT("open"), TEXT("access"),
    TEXT("data"), TEXT("content"), TEXT("body"), TEXT("payload"),

    // 뷰/템플릿 조작
    TEXT("view"), TEXT("template"), TEXT("tmpl"), TEXT("tpl"), TEXT("layout"), TEXT("theme"),
    TEXT("render"), TEXT("display"), TEXT("show"),

    // 콜백/웹훅
    TEXT("callback"), TEXT("callback_url"), TEXT("callbackurl"), TEXT("callbackUrl"),
    TEXT("webhook"), TEXT("webhookurl"), TEXT("webhook_url"), TEXT("notify"), TEXT("notify_url"),
    TEXT("ping"), TEXT("pingback"),

    // API/GraphQL 관련
    TEXT("query"), TEXT("mutation"), TEXT("subscription"),
    TEXT("endpoint"), TEXT("api"), TEXT("api_endpoint"), TEXT("api_url"),
    TEXT("service"), TEXT("service_url"), TEXT("proxy"), TEXT("proxy_url"),
    TEXT("upstream"), TEXT("backend"), TEXT("host"), TEXT("hostname"),

    // 데이터베이스/쿼리
    TEXT("sql"), TEXT("query"), TEXT("search"), TEXT("filter"), TEXT("where"), TEXT("order"), TEXT("sort"),
    TEXT("limit"), TEXT("offset"), TEXT("skip"), TEXT("take"),
    TEXT("table"), TEXT("collection"), TEXT("index"),

    // 파일 시스템
    TEXT("dir"), TEXT("directory"), TEXT("folder"), TEXT("location"),
    TEXT("base"), TEXT("basedir"), TEXT("base_dir"), TEXT("root"), TEXT("rootdir"),
    TEXT("upload_dir"), TEXT("uploaddir"), TEXT("tmp"), TEXT("temp"), TEXT("cache"),

    // 명령 실행 관련
    TEXT("cmd"), TEXT("command"), TEXT("exec"), TEXT("execute"), TEXT("run"), TEXT("shell"),
    TEXT("script"), TEXT("code"), TEXT("eval"), TEXT("expression"),

    // 기타 위험 파라미터
    TEXT("out"), TEXT("output"), TEXT("exit"), TEXT("site"), TEXT("domain"),
    TEXT("referrer"), TEXT("referer"), TEXT("from"), TEXT("origin"),
    TEXT("action"), TEXT("method"), TEXT("function"), TEXT("handler"),
    TEXT("debug"), TEXT("test"), TEXT("admin"), TEXT("config"), TEXT("setting")
};

const std::unordered_set<WORD> g_SuspiciousPortList =
{
    // 유명 백도어/트로이목마 포트
    31337,                                              // Back Orifice, Baron Night, BO2K
    12345, 12346,                                       // NetBus, Whack-a-mole
    27374,                                              // Sub Seven
    1243,                                               // Sub Seven (alternative)
    6666, 6667, 6668, 6669,                             // IRC 백도어, Vampyre

    // RAT (Remote Access Trojan)
    1337,                                               // WASTE
    5000, 5001, 5555, 5556,                             // 다양한 RAT
    9090,                                               // TeamViewer (악용 가능)
    8080, 8888,                                         // 프록시/웹 서버 (악용)

    // 프록시/터널링/SOCKS
    1080,                                               // SOCKS proxy
    3128,                                               // Squid proxy
    8123,                                               // Polipo proxy
    9050, 9051,                                         // Tor SOCKS, Control

    // C2 (Command & Control) 서버
    4444,                                               // Metasploit, msfvenom reverse shell
    4445, 4446,                                         // C2 alternatives
    5555,                                               // ADB, C2
    7777,                                               // Oracle, C2
    8000, 8001, 8008,                                   // 대체 HTTP
    9999, 10000,                                        // C2 common

    // 암호화폐 채굴
    3333,                                               // Stratum mining
    3334, 3335,                                         // Alternative Stratum
    8332, 8333,                                         // Bitcoin RPC, P2P
    18332, 18333,                                       // Bitcoin testnet
    9332,                                               // Litecoin

    // 랜섬웨어 관련
    20, 21, 22,                                         // FTP, SSH (데이터 유출)
    139, 445,                                           // SMB (WannaCry, NotPetya)
    3389,                                               // RDP (Ransomware 전파)

    // IoT 봇넷
    23,                                                 // Telnet (Mirai)
    2323,                                               // Telnet alternative
    37215,                                              // Mirai scanner
    48101,                                              // Mirai

    // 데이터베이스 (비정상 외부 노출)
    1433,                                               // MS SQL
    1521,                                               // Oracle
    3306,                                               // MySQL/MariaDB
    5432,                                               // PostgreSQL
    5984,                                               // CouchDB
    6379,                                               // Redis
    7000, 7001,                                         // Cassandra
    9042,                                               // Cassandra CQL
    9200, 9300,                                         // Elasticsearch
    27017, 27018,                                       // MongoDB

    // 관리 인터페이스
    2082, 2083,                                         // cPanel
    2086, 2087,                                         // WHM
    8443,                                               // Plesk, alternative HTTPS
    10000,                                              // Webmin

    // VPN/터널
    500, 4500,                                          // IPsec
    1194,                                               // OpenVPN
    1701, 1723,                                         // L2TP, PPTP

    // 기타 의심 포트
    2222,                                               // SSH alternative 
    4443,                                               // HTTPS alternative
    6660, 6661, 6662, 6663, 6664, 6665,                 // IRC (C2)
    7000,                                               // Afs3-fileserver, Kazaa
    8181,                                               // HTTP alternative
    9001,                                               // Tor, HSQLDB
    11211,                                              // Memcached (DDoS amplification)

    // DNS over HTTPS/TLS (우회 시도)
    853,                                                // DNS over TLS

    // 2024 악성코드 포트 
    2375, 2376,                                         // Docker API (악용)
    6443,                                               // Kubernetes API
    8000,                                               // Docker registry
    50000,                                              // SAP, Jenkins

    // 컨테이너/오케스트레이션
    2377, 2379, 2380,                                   // Docker Swarm, etcd
    10250, 10255,                                       // Kubelet
    8001, 8002,                                         // Kubernetes alternative APIs
    5000, 5001,                                         // Docker Registry
    9000,                                               // Portainer

    // NoSQL 데이터베이스 추가
    5984, 5985,                                         // CouchDB
    8086, 8088,                                         // InfluxDB
    7474, 7473, 7687,                                   // Neo4j
    8091, 8092, 8093,                                   // Couchbase
    28015, 29015,                                       // RethinkDB

    // 메시지 큐/스트리밍 
    5672, 15672,                                        // RabbitMQ
    9092, 9093,                                         // Kafka
    4222, 6222, 8222,                                   // NATS
    1883, 8883,                                         // MQTT
    6379,                                               // Redis

    // 모니터링/메트릭 
    3000,                                               // Grafana
    9090, 9091,                                         // Prometheus
    4040,                                               // Spark UI
    8080, 8081,                                         // Jenkins, Tomcat
    8888,                                               // Jupyter Notebook

    // 클라우드 서비스
    10001, 10002,                                       // Ubiquiti
    8291,                                               // MikroTik
    5555, 5556,                                         // HP Data Protector
    1900,                                               // UPnP (SSDP)

    // VoIP/통신
    5060, 5061,                                         // SIP
    5038,                                               // Asterisk Management

    // 백업/파일 전송
    2049,                                               // NFS
    873,                                                // rsync
    69,                                                 // TFTP
    20, 21,                                             // FTP (데이터, 제어)

    // 원격 접속 추가
    5900, 5901, 5902,                                   // VNC
    5631, 5632,                                         // pcAnywhere
    10000, 20000,                                       // Webmin, DNP3

    // 산업 제어 시스템 (ICS/SCADA)
    502,                                                // Modbus
    102,                                                // S7comm (Siemens)
    44818,                                              // EtherNet/IP
    20000,                                              // DNP3
    47808,                                              // BACnet

    // IoT 디바이스
    554,                                                // RTSP (IP 카메라)
    8000, 8080, 8081,                                   // 웹캠, IP 카메라
    9100,                                               // 프린터 (JetDirect)
    515,                                                // LPD (프린터)
    631,                                                // IPP (프린터)

    // P2P/파일 공유
    6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889,   // BitTorrent
    6346,                                               // Gnutella
    4662, 4672,                                         // eMule

    // 개발/디버깅
    5858,                                               // Java RMI
    9229,                                               // Node.js Inspector
    5005,                                               // Java Debug Wire Protocol
    4000,                                               // Erlang Port Mapper Daemon
    8983,                                               // Solr Admin
    9200, 9300,                                         // Elasticsearch

    // 2024-2025 랜섬웨어/봇넷 포트
    65000, 65001, 65002,                                // 동적 할당 고위험 포트
    49152, 49153, 49154,                                // Dynamic ports (악용)

    // 기타 고위험 서비스
    111,                                                // RPC portmapper
    135,                                                // MS RPC
    161, 162,                                           // SNMP
    389, 636,                                           // LDAP, LDAPS
    512, 513, 514,                                      // rexec, rlogin, rsh
    1433, 1434,                                         // MS SQL
    3306,                                               // MySQL
    5432,                                               // PostgreSQL
};

const std::unordered_map<std::tstring, std::tstring> g_BrandList =
{
    // ==================== 글로벌 테크 기업 ==================== //
    // Apple Ecosystem
    { TEXT("apple"), TEXT("apple.com") },
    {TEXT("icloud"), TEXT("icloud.com")},
    {TEXT("itunes"), TEXT("apple.com")},
    {TEXT("appleid"), TEXT("apple.com")},
    {TEXT("appstore"), TEXT("apple.com")},
    {TEXT("applemusic"), TEXT("apple.com")},
    {TEXT("applepay"), TEXT("apple.com")},
    {TEXT("iphone"), TEXT("apple.com")},
    {TEXT("ipad"), TEXT("apple.com")},
    {TEXT("macbook"), TEXT("apple.com")},
    {TEXT("applewatch"), TEXT("apple.com")},
    {TEXT("facetime"), TEXT("apple.com")},
    {TEXT("imessage"), TEXT("apple.com")},

    // Google Ecosystem
    { TEXT("google"), TEXT("google.com") },
    { TEXT("gmail"), TEXT("gmail.com") },
    { TEXT("youtube"), TEXT("youtube.com") },
    { TEXT("android"), TEXT("android.com") },
    { TEXT("googleplay"), TEXT("google.com") },
    { TEXT("googledrive"), TEXT("google.com") },
    { TEXT("googlepay"), TEXT("google.com") },
    { TEXT("googlecloud"), TEXT("google.com") },
    { TEXT("googleads"), TEXT("google.com") },
    { TEXT("googlemaps"), TEXT("google.com") },
    { TEXT("googlevoice"), TEXT("google.com") },
    { TEXT("chromebook"), TEXT("google.com") },
    { TEXT("googlefi"), TEXT("google.com") },

    // Microsoft Ecosystem
    { TEXT("microsoft"), TEXT("microsoft.com") },
    { TEXT("windows"), TEXT("microsoft.com") },
    { TEXT("live"), TEXT("live.com") },
    { TEXT("outlook"), TEXT("outlook.com") },
    { TEXT("onedrive"), TEXT("live.com") },
    { TEXT("azure"), TEXT("azure.com") },
    { TEXT("office"), TEXT("office.com") },
    { TEXT("office365"), TEXT("office.com") },
    { TEXT("xbox"), TEXT("xbox.com") },
    { TEXT("skype"), TEXT("skype.com") },
    { TEXT("teams"), TEXT("microsoft.com") },
    { TEXT("bing"), TEXT("bing.com") },
    { TEXT("msn"), TEXT("msn.com") },
    { TEXT("windowsphone"), TEXT("microsoft.com") },

    // Amazon Ecosystem
    { TEXT("amazon"), TEXT("amazon.com") },
    { TEXT("aws"), TEXT("amazon.com") },
    { TEXT("prime"), TEXT("amazon.com") },
    { TEXT("primevideo"), TEXT("amazon.com") },
    { TEXT("kindleunlimited"), TEXT("amazon.com") },
    { TEXT("kindle"), TEXT("amazon.com") },
    { TEXT("alexa"), TEXT("amazon.com") },
    { TEXT("amazonpay"), TEXT("amazon.com") },
    { TEXT("audible"), TEXT("amazon.com") },
    { TEXT("wholefoods"), TEXT("amazon.com") },
    { TEXT("twitch"), TEXT("twitch.tv") },

    // Meta Ecosystem
    { TEXT("facebook"), TEXT("facebook.com") },
    { TEXT("instagram"), TEXT("instagram.com") },
    { TEXT("whatsapp"), TEXT("whatsapp.com") },
    { TEXT("messenger"), TEXT("facebook.com") },
    { TEXT("meta"), TEXT("meta.com") },
    { TEXT("threads"), TEXT("threads.net") },
    { TEXT("oculus"), TEXT("oculus.com") },

    // ==================== 소셜 미디어 ==================== //
    { TEXT("twitter"), TEXT("twitter.com") },
    { TEXT("x"), TEXT("x.com") },
    { TEXT("linkedin"), TEXT("linkedin.com") },
    { TEXT("tiktok"), TEXT("tiktok.com") },
    { TEXT("snapchat"), TEXT("snapchat.com") },
    { TEXT("pinterest"), TEXT("pinterest.com") },
    { TEXT("reddit"), TEXT("reddit.com") },
    { TEXT("tumblr"), TEXT("tumblr.com") },
    { TEXT("discord"), TEXT("discord.com") },
    { TEXT("telegram"), TEXT("telegram.org") },
    { TEXT("signal"), TEXT("signal.org") },
    { TEXT("wechat"), TEXT("wechat.com") },
    { TEXT("line"), TEXT("line.me") },
    { TEXT("viber"), TEXT("viber.com") },
    { TEXT("kakao"), TEXT("kakao.com") },
    { TEXT("kakaotalk"), TEXT("kakao.com") },
    { TEXT("band"), TEXT("band.us") },

    // ==================== 글로벌 금융 기관 ==================== //

    // Payment Processors
    { TEXT("paypal"), TEXT("paypal.com") },
    { TEXT("stripe"), TEXT("stripe.com") },
    { TEXT("square"), TEXT("square.com") },
    { TEXT("venmo"), TEXT("venmo.com") },
    { TEXT("cashapp"), TEXT("cash.app") },
    { TEXT("zelle"), TEXT("zellepay.com") },
    { TEXT("wise"), TEXT("wise.com") },
    { TEXT("transferwise"), TEXT("wise.com") },
    { TEXT("revolut"), TEXT("revolut.com") },
    { TEXT("klarna"), TEXT("klarna.com") },
    { TEXT("afterpay"), TEXT("afterpay.com") },
    { TEXT("affirm"), TEXT("affirm.com") },

    // Credit Cards
    { TEXT("visa"), TEXT("visa.com") },
    { TEXT("mastercard"), TEXT("mastercard.com") },
    { TEXT("amex"), TEXT("americanexpress.com") },
    { TEXT("americanexpress"), TEXT("americanexpress.com") },
    { TEXT("discover"), TEXT("discover.com") },
    { TEXT("dinersclub"), TEXT("dinersclub.com") },
    { TEXT("jcb"), TEXT("jcb.com") },
    { TEXT("unionpay"), TEXT("unionpay.com") },

    // US Banks
    { TEXT("chase"), TEXT("chase.com") },
    { TEXT("jpmorgan"), TEXT("jpmorgan.com") },
    { TEXT("wellsfargo"), TEXT("wellsfargo.com") },
    { TEXT("bankofamerica"), TEXT("bankofamerica.com") },
    { TEXT("citibank"), TEXT("citi.com") },
    { TEXT("citi"), TEXT("citi.com") },
    { TEXT("usbank"), TEXT("usbank.com") },
    { TEXT("pnc"), TEXT("pnc.com") },
    { TEXT("capitalone"), TEXT("capitalone.com") },
    { TEXT("tdbank"), TEXT("tdbank.com") },
    { TEXT("schwab"), TEXT("schwab.com") },
    { TEXT("fidelity"), TEXT("fidelity.com") },
    { TEXT("morganstanley"), TEXT("morganstanley.com") },
    { TEXT("goldmansachs"), TEXT("goldmansachs.com") },

    // European Banks
    { TEXT("hsbc"), TEXT("hsbc.com") },
    { TEXT("barclays"), TEXT("barclays.com") },
    { TEXT("lloyds"), TEXT("lloydsbank.com") },
    { TEXT("santander"), TEXT("santander.com") },
    { TEXT("bnpparibas"), TEXT("bnpparibas.com") },
    { TEXT("deutschebank"), TEXT("db.com") },
    { TEXT("commerzbank"), TEXT("commerzbank.com") },
    { TEXT("ing"), TEXT("ing.com") },
    { TEXT("abn"), TEXT("abnamro.com") },
    { TEXT("ubs"), TEXT("ubs.com") },
    { TEXT("creditsuisse"), TEXT("credit-suisse.com") },

    // Asian Banks
    { TEXT("dbs"), TEXT("dbs.com") },
    { TEXT("ocbc"), TEXT("ocbc.com") },
    { TEXT("uob"), TEXT("uob.com") },
    { TEXT("icbc"), TEXT("icbc.com.cn") },
    { TEXT("boc"), TEXT("boc.cn") },
    { TEXT("ccb"), TEXT("ccb.com") },
    { TEXT("mitsubishi"), TEXT("mufg.jp") },
    { TEXT("mizuho"), TEXT("mizuhogroup.com") },
    { TEXT("smbc"), TEXT("smbc.co.jp") },

    // ==================== 한국 금융 & 핀테크 ==================== //

    // 포털/플랫폼
    { TEXT("naver"), TEXT("naver.com") },
    { TEXT("naverpay"), TEXT("naver.com") },
    { TEXT("daum"), TEXT("daum.net") },
    { TEXT("nate"), TEXT("nate.com") },

    // 모바일 금융
    { TEXT("toss"), TEXT("toss.im") },
    { TEXT("kakaopay"), TEXT("kakaopay.com") },
    { TEXT("kakaobank"), TEXT("kakaobank.com") },
    { TEXT("kbank"), TEXT("kbank.com") },
    { TEXT("payco"), TEXT("payco.com") },
    { TEXT("ssgpay"), TEXT("ssgpay.com") },
    { TEXT("lpay"), TEXT("lpay.com") },
    { TEXT("samsungpay"), TEXT("samsung.com") },
    { TEXT("naverfincorp"), TEXT("naverfincorp.com") },
    { TEXT("ktmmobile"), TEXT("ktmmobile.com") },
    { TEXT("sk7mobile"), TEXT("sk7mobile.com") },

    // 은행
    { TEXT("kbstar"), TEXT("kbstar.com") },
    { TEXT("kbbank"), TEXT("kbstar.com") },
    { TEXT("shinhan"), TEXT("shinhan.com") },
    { TEXT("shinhanbank"), TEXT("shinhan.com") },
    { TEXT("hanabank"), TEXT("hanabank.com") },
    { TEXT("wooribank"), TEXT("wooribank.com") },
    { TEXT("nhbank"), TEXT("banking.nonghyup.com") },
    { TEXT("ibk"), TEXT("ibk.co.kr") },
    { TEXT("bnkbusan"), TEXT("busanbank.co.kr") },
    { TEXT("dgb"), TEXT("dgb.co.kr") },
    { TEXT("kjbank"), TEXT("kjbank.com") },
    { TEXT("jbbank"), TEXT("jbbank.co.kr") },
    { TEXT("kdbbank"), TEXT("kdb.co.kr") },
    { TEXT("suhyup"), TEXT("suhyup.co.kr") },
    { TEXT("kfcc"), TEXT("kfcc.co.kr") },
    { TEXT("kakaobank"), TEXT("kakaobank.com") },
    { TEXT("kbank"), TEXT("kbank.com") },
    { TEXT("tossbank"), TEXT("tossbank.com") },

    // 카드사
    { TEXT("shinhancard"), TEXT("shinhancard.com") },
    { TEXT("kbcard"), TEXT("kbcard.com") },
    { TEXT("hanacard"), TEXT("hanacard.co.kr") },
    { TEXT("hyundaicard"), TEXT("hyundaicard.com") },
    { TEXT("samsungcard"), TEXT("samsungcard.com") },
    { TEXT("lottecard"), TEXT("lottecard.co.kr") },
    { TEXT("bccard"), TEXT("bccard.com") },
    { TEXT("nhcard"), TEXT("nhcard.com") },
    { TEXT("wooricard"), TEXT("wooricard.com") },
    { TEXT("citicard"), TEXT("citicard.co.kr") },

    // 증권사
    { TEXT("miraeasset"), TEXT("miraeasset.com") },
    { TEXT("kiwoom"), TEXT("kiwoom.com") },
    { TEXT("nhqv"), TEXT("nhqv.com") },
    { TEXT("kbsec"), TEXT("kbsec.com") },
    { TEXT("samsungpop"), TEXT("samsungpop.com") },
    { TEXT("shinhansec"), TEXT("shinhan.com") },
    { TEXT("hanaw"), TEXT("hanaw.com") },
    { TEXT("truefriend"), TEXT("truefriend.com") },

    // 보험사
    { TEXT("samsungfire"), TEXT("samsungfire.com") },
    { TEXT("samsunglife"), TEXT("samsunglife.com") },
    { TEXT("meritzfire"), TEXT("meritzfire.com") },
    { TEXT("hanwhalife"), TEXT("hanwhalife.com") },
    { TEXT("db"), TEXT("idbins.com") },
    { TEXT("kbinsure"), TEXT("kbinsure.co.kr") },
    { TEXT("heungkukfire"), TEXT("heungkukfire.co.kr") },
    { TEXT("dongbu"), TEXT("idongbu.com") },

    // ==================== 암호화폐 ==================== //
    { TEXT("binance"), TEXT("binance.com") },
    { TEXT("coinbase"), TEXT("coinbase.com") },
    { TEXT("kraken"), TEXT("kraken.com") },
    { TEXT("bitfinex"), TEXT("bitfinex.com") },
    { TEXT("bitstamp"), TEXT("bitstamp.net") },
    { TEXT("kucoin"), TEXT("kucoin.com") },
    { TEXT("huobi"), TEXT("huobi.com") },
    { TEXT("okx"), TEXT("okx.com") },
    { TEXT("bybit"), TEXT("bybit.com") },
    { TEXT("ftx"), TEXT("ftx.com") },
    { TEXT("crypto.com"), TEXT("crypto.com") },
    { TEXT("blockchain"), TEXT("blockchain.com") },
    { TEXT("metamask"), TEXT("metamask.io") },
    { TEXT("trustwallet"), TEXT("trustwallet.com") },
    { TEXT("ledger"), TEXT("ledger.com") },
    { TEXT("trezor"), TEXT("trezor.io") },
    { TEXT("exodus"), TEXT("exodus.com") },
    { TEXT("coinomi"), TEXT("coinomi.com") },
    { TEXT("myetherwallet"), TEXT("myetherwallet.com") },
    { TEXT("upbit"), TEXT("upbit.com") },
    { TEXT("bithumb"), TEXT("bithumb.com") },
    { TEXT("korbit"), TEXT("korbit.co.kr") },
    { TEXT("coinone"), TEXT("coinone.co.kr") },
    { TEXT("gopax"), TEXT("gopax.co.kr") },
    { TEXT("okbit"), TEXT("okbit.co.kr") },

    // ==================== 이커머스 ==================== //
    { TEXT("ebay"), TEXT("ebay.com") },
    { TEXT("etsy"), TEXT("etsy.com") },
    { TEXT("alibaba"), TEXT("alibaba.com") },
    { TEXT("aliexpress"), TEXT("aliexpress.com") },
    { TEXT("taobao"), TEXT("taobao.com") },
    { TEXT("tmall"), TEXT("tmall.com") },
    { TEXT("walmart"), TEXT("walmart.com") },
    { TEXT("target"), TEXT("target.com") },
    { TEXT("bestbuy"), TEXT("bestbuy.com") },
    { TEXT("costco"), TEXT("costco.com") },
    { TEXT("homedepot"), TEXT("homedepot.com") },
    { TEXT("lowes"), TEXT("lowes.com") },
    { TEXT("wayfair"), TEXT("wayfair.com") },
    { TEXT("overstock"), TEXT("overstock.com") },
    { TEXT("newegg"), TEXT("newegg.com") },
    { TEXT("shopify"), TEXT("shopify.com") },
    { TEXT("rakuten"), TEXT("rakuten.com") },
    { TEXT("mercari"), TEXT("mercari.com") },
    { TEXT("poshmark"), TEXT("poshmark.com") },
    { TEXT("depop"), TEXT("depop.com") },
    { TEXT("wish"), TEXT("wish.com") },
    { TEXT("jd"), TEXT("jd.com") },
    { TEXT("pinduoduo"), TEXT("pinduoduo.com") },

    // 한국 이커머스
    { TEXT("coupang"), TEXT("coupang.com") },
    { TEXT("11st"), TEXT("11st.co.kr") },
    { TEXT("gmarket"), TEXT("gmarket.co.kr") },
    { TEXT("auction"), TEXT("auction.co.kr") },
    { TEXT("interpark"), TEXT("interpark.com") },
    { TEXT("wemakeprice"), TEXT("wemakeprice.com") },
    { TEXT("ticketmonster"), TEXT("ticketmonster.co.kr") },
    { TEXT("tmon"), TEXT("tmon.co.kr") },
    { TEXT("ssg"), TEXT("ssg.com") },
    { TEXT("lotte"), TEXT("lotte.com") },
    { TEXT("lotteimall"), TEXT("lotte.com") },
    { TEXT("hmall"), TEXT("hmall.com") },
    { TEXT("gsshop"), TEXT("gsshop.com") },
    { TEXT("cjmall"), TEXT("cjmall.com") },
    { TEXT("nsmall"), TEXT("nsmall.com") },
    { TEXT("oliveyoung"), TEXT("oliveyoung.co.kr") },
    { TEXT("kurly"), TEXT("kurly.com") },
    { TEXT("marketkurly"), TEXT("kurly.com") },
    { TEXT("oasis"), TEXT("oasis.co.kr") },
    { TEXT("musinsa"), TEXT("musinsa.com") },
    { TEXT("zigzag"), TEXT("zigzag.kr") },
    { TEXT("ably"), TEXT("a-bly.com") },
    { TEXT("brandi"), TEXT("brandi.co.kr") },

    // ==================== 배달 주문 ==================== //
    { TEXT("ubereats"), TEXT("ubereats.com") },
    { TEXT("doordash"), TEXT("doordash.com") },
    { TEXT("grubhub"), TEXT("grubhub.com") },
    { TEXT("postmates"), TEXT("postmates.com") },
    { TEXT("deliveroo"), TEXT("deliveroo.com") },
    { TEXT("zomato"), TEXT("zomato.com") },
    { TEXT("swiggy"), TEXT("swiggy.com") },
    { TEXT("foodpanda"), TEXT("foodpanda.com") },

    // 한국 배달 
    { TEXT("baemin"), TEXT("baemin.com") },
    { TEXT("baedal"), TEXT("baemin.com") },
    { TEXT("yogiyo"), TEXT("yogiyo.co.kr") },
    { TEXT("coupangeats"), TEXT("coupangeats.com") },
    { TEXT("ddingdong"), TEXT("ddingdong.com") },

    // ==================== 여행 & 숙박 ==================== //
    { TEXT("booking"), TEXT("booking.com") },
    { TEXT("expedia"), TEXT("expedia.com") },
    { TEXT("airbnb"), TEXT("airbnb.com") },
    { TEXT("hotels"), TEXT("hotels.com") },
    { TEXT("trivago"), TEXT("trivago.com") },
    { TEXT("priceline"), TEXT("priceline.com") },
    { TEXT("kayak"), TEXT("kayak.com") },
    { TEXT("skyscanner"), TEXT("skyscanner.com") },
    { TEXT("agoda"), TEXT("agoda.com") },
    { TEXT("trip"), TEXT("trip.com") },
    { TEXT("tripadvisor"), TEXT("tripadvisor.com") },
    { TEXT("marriott"), TEXT("marriott.com") },
    { TEXT("hilton"), TEXT("hilton.com") },
    { TEXT("hyatt"), TEXT("hyatt.com") },
    { TEXT("ihg"), TEXT("ihg.com") },
    { TEXT("accor"), TEXT("accor.com") },

    // 한국 여행
    { TEXT("yanolja"), TEXT("yanolja.com") },
    { TEXT("goodchoice"), TEXT("goodchoice.kr") },
    { TEXT("yeogi"), TEXT("yeogi.com") },
    { TEXT("interparktour"), TEXT("interpark.com") },
    { TEXT("modetour"), TEXT("modetour.com") },
    { TEXT("hanatour"), TEXT("hanatour.com") },

    // 항공사
    { TEXT("delta"), TEXT("delta.com") },
    { TEXT("united"), TEXT("united.com") },
    { TEXT("american"), TEXT("aa.com") },
    { TEXT("southwest"), TEXT("southwest.com") },
    { TEXT("jetblue"), TEXT("jetblue.com") },
    { TEXT("lufthansa"), TEXT("lufthansa.com") },
    { TEXT("britishairways"), TEXT("ba.com") },
    { TEXT("airfrance"), TEXT("airfrance.com") },
    { TEXT("klm"), TEXT("klm.com") },
    { TEXT("emirates"), TEXT("emirates.com") },
    { TEXT("qantas"), TEXT("qantas.com") },
    { TEXT("singaporeair"), TEXT("singaporeair.com") },
    { TEXT("ana"), TEXT("ana.co.jp") },
    { TEXT("jal"), TEXT("jal.com") },
    { TEXT("koreanair"), TEXT("koreanair.com") },
    { TEXT("asiana"), TEXT("flyasiana.com") },
    { TEXT("jejuair"), TEXT("jejuair.net") },
    { TEXT("jinair"), TEXT("jinair.com") },
    { TEXT("tway"), TEXT("twayair.com") },
    { TEXT("airbusan"), TEXT("airbusan.com") },

    // ==================== 배송 & 물류 ==================== //
    { TEXT("fedex"), TEXT("fedex.com") },
    { TEXT("ups"), TEXT("ups.com") },
    { TEXT("dhl"), TEXT("dhl.com") },
    { TEXT("usps"), TEXT("usps.com") },
    { TEXT("royalmail"), TEXT("royalmail.com") },
    { TEXT("deutschepost"), TEXT("deutschepost.de") },
    { TEXT("canadapost"), TEXT("canadapost.ca") },
    { TEXT("auspost"), TEXT("auspost.com.au") },

    // 한국 배송
    { TEXT("cjlogistics"), TEXT("cjlogistics.com") },
    { TEXT("epost"), TEXT("epost.go.kr") },
    { TEXT("hanjin"), TEXT("hanjin.co.kr") },
    { TEXT("lotte"), TEXT("lotteglogis.com") },
    { TEXT("kgbls"), TEXT("kgbls.co.kr") },
    { TEXT("ilogen"), TEXT("ilogen.com") },

    // ==================== 스트리밍 & 엔터테인먼트 ==================== //
    { TEXT("netflix"), TEXT("netflix.com") },
    { TEXT("hulu"), TEXT("hulu.com") },
    { TEXT("disneyplus"), TEXT("disneyplus.com") },
    { TEXT("disney"), TEXT("disney.com") },
    { TEXT("hbomax"), TEXT("hbomax.com") },
    { TEXT("hbo"), TEXT("hbo.com") },
    { TEXT("paramountplus"), TEXT("paramountplus.com") },
    { TEXT("peacock"), TEXT("peacocktv.com") },
    { TEXT("appletv"), TEXT("apple.com") },
    { TEXT("crunchyroll"), TEXT("crunchyroll.com") },
    { TEXT("funimation"), TEXT("funimation.com") },
    { TEXT("viki"), TEXT("viki.com") },

    // 음악 스트리밍
    { TEXT("spotify"), TEXT("spotify.com") },
    { TEXT("applemusic"), TEXT("apple.com") },
    { TEXT("pandora"), TEXT("pandora.com") },
    { TEXT("soundcloud"), TEXT("soundcloud.com") },
    { TEXT("tidal"), TEXT("tidal.com") },
    { TEXT("deezer"), TEXT("deezer.com") },
    { TEXT("youtubemusic"), TEXT("youtube.com") },

    // 한국 스트리밍
    { TEXT("wavve"), TEXT("wavve.com") },
    { TEXT("tving"), TEXT("tving.com") },
    { TEXT("watcha"), TEXT("watcha.com") },
    { TEXT("laftel"), TEXT("laftel.net") },
    { TEXT("serieson"), TEXT("serieson.naver.com") },
    { TEXT("melonticket"), TEXT("melon.com") },
    { TEXT("genie"), TEXT("genie.co.kr") },
    { TEXT("bugs"), TEXT("bugs.co.kr") },
    { TEXT("flo"), TEXT("music-flo.com") },
    { TEXT("vibe"), TEXT("vibe.naver.com") },

    // ==================== 게임 플랫폼 ==================== //
    { TEXT("steam"), TEXT("steampowered.com") },
    { TEXT("epicgames"), TEXT("epicgames.com") },
    { TEXT("origin"), TEXT("origin.com") },
    { TEXT("ea"), TEXT("ea.com") },
    { TEXT("ubisoft"), TEXT("ubisoft.com") },
    { TEXT("uplay"), TEXT("ubisoft.com") },
    { TEXT("blizzard"), TEXT("blizzard.com") },
    { TEXT("battlenet"), TEXT("battle.net") },
    { TEXT("riotgames"), TEXT("riotgames.com") },
    { TEXT("leagueoflegends"), TEXT("leagueoflegends.com") },
    { TEXT("valorant"), TEXT("valorant.com") },
    { TEXT("playstation"), TEXT("playstation.com") },
    { TEXT("psn"), TEXT("playstation.com") },
    { TEXT("xbox"), TEXT("xbox.com") },
    { TEXT("nintendo"), TEXT("nintendo.com") },
    { TEXT("eshop"), TEXT("nintendo.com") },
    { TEXT("gog"), TEXT("gog.com") },
    { TEXT("itch"), TEXT("itch.io") },
    { TEXT("greenmangaming"), TEXT("greenmangaming.com") },
    { TEXT("humblebundle"), TEXT("humblebundle.com") },
    { TEXT("gamesplanet"), TEXT("gamesplanet.com") },
    { TEXT("nexon"), TEXT("nexon.com") },
    { TEXT("ncsoft"), TEXT("ncsoft.com") },
    { TEXT("nexongt"), TEXT("nexon.com") },
    { TEXT("netmarble"), TEXT("netmarble.com") },
    { TEXT("smilegate"), TEXT("smilegate.com") },
    { TEXT("krafton"), TEXT("krafton.com") },
    { TEXT("pubg"), TEXT("pubg.com") },
    { TEXT("roblox"), TEXT("roblox.com") },
    { TEXT("minecraft"), TEXT("minecraft.net") },
    { TEXT("fortnite"), TEXT("epicgames.com") },
    { TEXT("callofduty"), TEXT("callofduty.com") },
    { TEXT("apex"), TEXT("ea.com") },

    // ==================== 통신사 ==================== //

    // 글로벌 통신사
    { TEXT("att"), TEXT("att.com") },
    { TEXT("verizon"), TEXT("verizon.com") },
    { TEXT("t-mobile"), TEXT("t-mobile.com") },
    { TEXT("sprint"), TEXT("sprint.com") },
    { TEXT("vodafone"), TEXT("vodafone.com") },
    { TEXT("orange"), TEXT("orange.com") },
    { TEXT("telefonica"), TEXT("telefonica.com") },
    { TEXT("telekom"), TEXT("telekom.com") },
    { TEXT("bt"), TEXT("bt.com") },
    { TEXT("rogers"), TEXT("rogers.com") },
    { TEXT("bell"), TEXT("bell.ca") },
    { TEXT("telus"), TEXT("telus.com") },
    { TEXT("telstra"), TEXT("telstra.com.au") },
    { TEXT("optus"), TEXT("optus.com.au") },
    { TEXT("softbank"), TEXT("softbank.jp") },
    { TEXT("docomo"), TEXT("docomo.ne.jp") },
    { TEXT("kddi"), TEXT("kddi.com") },
    { TEXT("chinaunicom"), TEXT("chinaunicom.com.cn") },
    { TEXT("chinamobile"), TEXT("chinamobile.com") },

    // 한국 통신사
    { TEXT("skt"), TEXT("sktelecom.com") },
    { TEXT("skbroadband"), TEXT("skbroadband.com") },
    { TEXT("kt"), TEXT("kt.com") },
    { TEXT("uplus"), TEXT("uplus.co.kr") },
    { TEXT("lguplus"), TEXT("uplus.co.kr") },

    // ==================== 클라우드 & SaaS ==================== //
    { TEXT("dropbox"), TEXT("dropbox.com") },
    { TEXT("box"), TEXT("box.com") },
    { TEXT("googledrive"), TEXT("google.com") },
    { TEXT("onedrive"), TEXT("microsoft.com") },
    { TEXT("icloud"), TEXT("icloud.com") },
    { TEXT("mega"), TEXT("mega.nz") },
    { TEXT("pcloud"), TEXT("pcloud.com") },
    { TEXT("sync"), TEXT("sync.com") },

    // 개발자 도구
    { TEXT("github"), TEXT("github.com") },
    { TEXT("gitlab"), TEXT("gitlab.com") },
    { TEXT("bitbucket"), TEXT("bitbucket.org") },
    { TEXT("atlassian"), TEXT("atlassian.com") },
    { TEXT("jira"), TEXT("atlassian.com") },
    { TEXT("confluence"), TEXT("atlassian.com") },
    { TEXT("trello"), TEXT("trello.com") },
    { TEXT("asana"), TEXT("asana.com") },
    { TEXT("monday"), TEXT("monday.com") },
    { TEXT("notion"), TEXT("notion.so") },
    { TEXT("evernote"), TEXT("evernote.com") },
    { TEXT("onenote"), TEXT("microsoft.com") },

    // 커뮤니케이션
    { TEXT("slack"), TEXT("slack.com") },
    { TEXT("zoom"), TEXT("zoom.us") },
    { TEXT("webex"), TEXT("webex.com") },
    { TEXT("gotomeeting"), TEXT("gotomeeting.com") },
    { TEXT("meet"), TEXT("meet.google.com") },
    { TEXT("teams"), TEXT("microsoft.com") },

    // 디자인
    { TEXT("adobe"), TEXT("adobe.com") },
    { TEXT("figma"), TEXT("figma.com") },
    { TEXT("canva"), TEXT("canva.com") },
    { TEXT("sketch"), TEXT("sketch.com") },
    { TEXT("invision"), TEXT("invisionapp.com") },

    // 도메인/호스팅
    { TEXT("godaddy"), TEXT("godaddy.com") },
    { TEXT("namecheap"), TEXT("namecheap.com") },
    { TEXT("bluehost"), TEXT("bluehost.com") },
    { TEXT("hostgator"), TEXT("hostgator.com") },
    { TEXT("siteground"), TEXT("siteground.com") },
    { TEXT("dreamhost"), TEXT("dreamhost.com") },
    { TEXT("squarespace"), TEXT("squarespace.com") },
    { TEXT("wix"), TEXT("wix.com") },
    { TEXT("weebly"), TEXT("weebly.com") },
    { TEXT("wordpress"), TEXT("wordpress.com") },

    // 클라우드 인프라
    { TEXT("cloudflare"), TEXT("cloudflare.com") },
    { TEXT("digitalocean"), TEXT("digitalocean.com") },
    { TEXT("linode"), TEXT("linode.com") },
    { TEXT("vultr"), TEXT("vultr.com") },
    { TEXT("heroku"), TEXT("heroku.com") },
    { TEXT("netlify"), TEXT("netlify.com") },
    { TEXT("vercel"), TEXT("vercel.com") },

    // IAM/SSO/인증 플랫폼
    { TEXT("okta"), TEXT("okta.com") },
    { TEXT("auth0"), TEXT("auth0.com") },
    { TEXT("onelogin"), TEXT("onelogin.com") },
    { TEXT("duo"), TEXT("duo.com") },
    { TEXT("duosecurity"), TEXT("duo.com") },
    { TEXT("pingidentity"), TEXT("pingidentity.com") },
    { TEXT("ping"), TEXT("pingidentity.com") },
    { TEXT("jumpcloud"), TEXT("jumpcloud.com") },
    { TEXT("centrify"), TEXT("centrify.com") },
    { TEXT("cyberark"), TEXT("cyberark.com") },
    { TEXT("forgerock"), TEXT("forgerock.com") },
    { TEXT("sailpoint"), TEXT("sailpoint.com") },
    { TEXT("entra"), TEXT("microsoft.com") },
    { TEXT("azuread"), TEXT("microsoft.com") },
    { TEXT("workspace"), TEXT("google.com") },
    { TEXT("gsuite"), TEXT("google.com") },

    // Password Managers
    { TEXT("lastpass"), TEXT("lastpass.com") },
    { TEXT("1password"), TEXT("1password.com") },
    { TEXT("dashlane"), TEXT("dashlane.com") },
    { TEXT("bitwarden"), TEXT("bitwarden.com") },
    { TEXT("keeper"), TEXT("keepersecurity.com") },
    { TEXT("nordpass"), TEXT("nordpass.com") },
    { TEXT("roboform"), TEXT("roboform.com") },
    { TEXT("passwordboss"), TEXT("passwordboss.com") },
    { TEXT("sticky"), TEXT("stickypassword.com") },
    { TEXT("logmeonce"), TEXT("logmeonce.com") },
    { TEXT("zoho"), TEXT("zoho.com") },

    // 엔터프라이즈 SaaS
    { TEXT("salesforce"), TEXT("salesforce.com") },
    { TEXT("docusign"), TEXT("docusign.com") },
    { TEXT("adobesign"), TEXT("adobesign.com") },
    { TEXT("hellosign"), TEXT("hellosign.com") },
    { TEXT("pandadoc"), TEXT("pandadoc.com") },
    { TEXT("servicenow"), TEXT("servicenow.com") },
    { TEXT("oracle"), TEXT("oracle.com") },
    { TEXT("sap"), TEXT("sap.com") },
    { TEXT("workday"), TEXT("workday.com") },
    { TEXT("successfactors"), TEXT("successfactors.com") },
    { TEXT("concur"), TEXT("concur.com") },
    { TEXT("netsuite"), TEXT("netsuite.com") },
    { TEXT("peoplesoft"), TEXT("oracle.com") },
    { TEXT("dynamics"), TEXT("dynamics.microsoft.com") },

    // CRM/마케팅
    { TEXT("hubspot"), TEXT("hubspot.com") },
    { TEXT("marketo"), TEXT("marketo.com") },
    { TEXT("mailchimp"), TEXT("mailchimp.com") },
    { TEXT("constantcontact"), TEXT("constantcontact.com") },
    { TEXT("sendinblue"), TEXT("sendinblue.com") },
    { TEXT("activecampaign"), TEXT("activecampaign.com") },
    { TEXT("pipedrive"), TEXT("pipedrive.com") },
    { TEXT("zendesk"), TEXT("zendesk.com") },
    { TEXT("freshdesk"), TEXT("freshdesk.com") },
    { TEXT("intercom"), TEXT("intercom.com") },
    { TEXT("drift"), TEXT("drift.com") },

    // 회계/재무
    { TEXT("quickbooks"), TEXT("quickbooks.intuit.com") },
    { TEXT("intuit"), TEXT("intuit.com") },
    { TEXT("xero"), TEXT("xero.com") },
    { TEXT("freshbooks"), TEXT("freshbooks.com") },
    { TEXT("wave"), TEXT("waveapps.com") },
    { TEXT("sage"), TEXT("sage.com") },
    { TEXT("netsuite"), TEXT("netsuite.com") },
    { TEXT("expensify"), TEXT("expensify.com") },
    { TEXT("billcom"), TEXT("bill.com") },
    { TEXT("coupa"), TEXT("coupa.com") },

    // HR/급여
    { TEXT("adp"), TEXT("adp.com") },
    { TEXT("paychex"), TEXT("paychex.com") },
    { TEXT("gusto"), TEXT("gusto.com") },
    { TEXT("bamboohr"), TEXT("bamboohr.com") },
    { TEXT("zenefits"), TEXT("zenefits.com") },
    { TEXT("namely"), TEXT("namely.com") },
    { TEXT("rippling"), TEXT("rippling.com") },
    { TEXT("justworks"), TEXT("justworks.com") },

    // 분석/BI
    { TEXT("tableau"), TEXT("tableau.com") },
    { TEXT("powerbi"), TEXT("powerbi.microsoft.com") },
    { TEXT("looker"), TEXT("looker.com") },
    { TEXT("domo"), TEXT("domo.com") },
    { TEXT("qlik"), TEXT("qlik.com") },
    { TEXT("sisense"), TEXT("sisense.com") },

    // ==================== 교육 플랫폼 & 기관 ==================== //

    // 온라인 교육 플랫폼
    { TEXT("coursera"), TEXT("coursera.org") },
    { TEXT("udemy"), TEXT("udemy.com") },
    { TEXT("edx"), TEXT("edx.org") },
    { TEXT("skillshare"), TEXT("skillshare.com") },
    { TEXT("linkedin"), TEXT("linkedin.com") },
    { TEXT("pluralsight"), TEXT("pluralsight.com") },
    { TEXT("codecademy"), TEXT("codecademy.com") },
    { TEXT("udacity"), TEXT("udacity.com") },
    { TEXT("khanacademy"), TEXT("khanacademy.org") },
    { TEXT("duolingo"), TEXT("duolingo.com") },
    { TEXT("rosettastone"), TEXT("rosettastone.com") },
    { TEXT("babbel"), TEXT("babbel.com") },

    // 학습관리시스템 (LMS)
    { TEXT("canvas"), TEXT("canvas.instructure.com") },
    { TEXT("instructure"), TEXT("instructure.com") },
    { TEXT("blackboard"), TEXT("blackboard.com") },
    { TEXT("moodle"), TEXT("moodle.org") },
    { TEXT("schoology"), TEXT("schoology.com") },
    { TEXT("brightspace"), TEXT("brightspace.com") },
    { TEXT("d2l"), TEXT("d2l.com") },
    { TEXT("edmodo"), TEXT("edmodo.com") },
    { TEXT("classlink"), TEXT("classlink.com") },
    { TEXT("clever"), TEXT("clever.com") },
    { TEXT("powerschool"), TEXT("powerschool.com") },
    { TEXT("infinite"), TEXT("infinitecampus.com") },
    { TEXT("skyward"), TEXT("skyward.com") },

    // 글로벌 대학 (미국)
    { TEXT("harvard"), TEXT("harvard.edu") },
    { TEXT("mit"), TEXT("mit.edu") },
    { TEXT("stanford"), TEXT("stanford.edu") },
    { TEXT("yale"), TEXT("yale.edu") },
    { TEXT("princeton"), TEXT("princeton.edu") },
    { TEXT("columbia"), TEXT("columbia.edu") },
    { TEXT("upenn"), TEXT("upenn.edu") },
    { TEXT("cornell"), TEXT("cornell.edu") },
    { TEXT("brown"), TEXT("brown.edu") },
    { TEXT("dartmouth"), TEXT("dartmouth.edu") },
    { TEXT("caltech"), TEXT("caltech.edu") },
    { TEXT("uchicago"), TEXT("uchicago.edu") },
    { TEXT("duke"), TEXT("duke.edu") },
    { TEXT("berkeley"), TEXT("berkeley.edu") },
    { TEXT("ucla"), TEXT("ucla.edu") },
    { TEXT("usc"), TEXT("usc.edu") },
    { TEXT("nyu"), TEXT("nyu.edu") },
    { TEXT("northwestern"), TEXT("northwestern.edu") },

    // 글로벌 대학 (영국)
    { TEXT("oxford"), TEXT("ox.ac.uk") },
    { TEXT("cambridge"), TEXT("cam.ac.uk") },
    { TEXT("imperial"), TEXT("imperial.ac.uk") },
    { TEXT("ucl"), TEXT("ucl.ac.uk") },
    { TEXT("lse"), TEXT("lse.ac.uk") },
    { TEXT("edinburgh"), TEXT("ed.ac.uk") },
    { TEXT("kcl"), TEXT("kcl.ac.uk") },
    { TEXT("manchester"), TEXT("manchester.ac.uk") },

    // 글로벌 대학 (기타)
    { TEXT("utoronto"), TEXT("utoronto.ca") },
    { TEXT("ubc"), TEXT("ubc.ca") },
    { TEXT("mcgill"), TEXT("mcgill.ca") },
    { TEXT("anu"), TEXT("anu.edu.au") },
    { TEXT("melbourne"), TEXT("unimelb.edu.au") },
    { TEXT("sydney"), TEXT("sydney.edu.au") },
    { TEXT("nus"), TEXT("nus.edu.sg") },
    { TEXT("ntu"), TEXT("ntu.edu.sg") },
    { TEXT("tsinghua"), TEXT("tsinghua.edu.cn") },
    { TEXT("pku"), TEXT("pku.edu.cn") },
    { TEXT("todai"), TEXT("u-tokyo.ac.jp") },
    { TEXT("kyoto-u"), TEXT("kyoto-u.ac.jp") },

    // 한국 주요 대학
    { TEXT("snu"), TEXT("snu.ac.kr") },
    { TEXT("서울대"), TEXT("snu.ac.kr") },
    { TEXT("yonsei"), TEXT("yonsei.ac.kr") },
    { TEXT("연세대"), TEXT("yonsei.ac.kr") },
    { TEXT("korea"), TEXT("korea.ac.kr") },
    { TEXT("고려대"), TEXT("korea.ac.kr") },
    { TEXT("kaist"), TEXT("kaist.ac.kr") },
    { TEXT("포항공대"), TEXT("postech.ac.kr") },
    { TEXT("postech"), TEXT("postech.ac.kr") },
    { TEXT("unist"), TEXT("unist.ac.kr") },
    { TEXT("dgist"), TEXT("dgist.ac.kr") },
    { TEXT("gist"), TEXT("gist.ac.kr") },
    { TEXT("skku"), TEXT("skku.edu") },
    { TEXT("성균관대"), TEXT("skku.edu") },
    { TEXT("hanyang"), TEXT("hanyang.ac.kr") },
    { TEXT("한양대"), TEXT("hanyang.ac.kr") },
    { TEXT("sogang"), TEXT("sogang.ac.kr") },
    { TEXT("서강대"), TEXT("sogang.ac.kr") },
    { TEXT("cau"), TEXT("cau.ac.kr") },
    { TEXT("중앙대"), TEXT("cau.ac.kr") },
    { TEXT("ewha"), TEXT("ewha.ac.kr") },
    { TEXT("이화여대"), TEXT("ewha.ac.kr") },
    { TEXT("kyunghee"), TEXT("khu.ac.kr") },
    { TEXT("경희대"), TEXT("khu.ac.kr") },
    { TEXT("sungshin"), TEXT("sungshin.ac.kr") },
    { TEXT("숙명여대"), TEXT("sookmyung.ac.kr") },

    // ==================== 보안 & 백신 ==================== //
    { TEXT("norton"), TEXT("norton.com") },
    { TEXT("mcafee"), TEXT("mcafee.com") },
    { TEXT("kaspersky"), TEXT("kaspersky.com") },
    { TEXT("avg"), TEXT("avg.com") },
    { TEXT("avast"), TEXT("avast.com") },
    { TEXT("bitdefender"), TEXT("bitdefender.com") },
    { TEXT("malwarebytes"), TEXT("malwarebytes.com") },
    { TEXT("eset"), TEXT("eset.com") },
    { TEXT("trendmicro"), TEXT("trendmicro.com") },
    { TEXT("sophos"), TEXT("sophos.com") },
    { TEXT("webroot"), TEXT("webroot.com") },
    { TEXT("ahnlab"), TEXT("ahnlab.com") },
    { TEXT("v3"), TEXT("ahnlab.com") },

    // ==================== 뉴스 & 미디어 ==================== //
    { TEXT("nytimes"), TEXT("nytimes.com") },
    { TEXT("washingtonpost"), TEXT("washingtonpost.com") },
    { TEXT("wsj"), TEXT("wsj.com") },
    { TEXT("cnn"), TEXT("cnn.com") },
    { TEXT("bbc"), TEXT("bbc.com") },
    { TEXT("reuters"), TEXT("reuters.com") },
    { TEXT("bloomberg"), TEXT("bloomberg.com") },
    { TEXT("forbes"), TEXT("forbes.com") },
    { TEXT("theguardian"), TEXT("theguardian.com") },

    // 한국 뉴스
    { TEXT("chosun"), TEXT("chosun.com") },
    { TEXT("joongang"), TEXT("joongang.co.kr") },
    { TEXT("donga"), TEXT("donga.com") },
    { TEXT("hankyung"), TEXT("hankyung.com") },
    { TEXT("mk"), TEXT("mk.co.kr") },
    { TEXT("khan"), TEXT("khan.co.kr") },
    { TEXT("hani"), TEXT("hani.co.kr") },
    { TEXT("ohmynews"), TEXT("ohmynews.com") },

    // ==================== 정부 & 공공기관 ==================== //

    // 미국 
    { TEXT("irs"), TEXT("irs.gov") },
    { TEXT("ssa"), TEXT("ssa.gov") },
    { TEXT("socialsecurity"), TEXT("ssa.gov") },
    { TEXT("usa.gov"), TEXT("usa.gov") },
    { TEXT("usps"), TEXT("usps.com") },
    { TEXT("dhs"), TEXT("dhs.gov") },
    { TEXT("fbi"), TEXT("fbi.gov") },
    { TEXT("ice"), TEXT("ice.gov") },
    { TEXT("uscis"), TEXT("uscis.gov") },
    { TEXT("state"), TEXT("state.gov") },
    { TEXT("dos"), TEXT("state.gov") },
    { TEXT("treasury"), TEXT("treasury.gov") },
    { TEXT("justice"), TEXT("justice.gov") },
    { TEXT("doj"), TEXT("justice.gov") },
    { TEXT("sec"), TEXT("sec.gov") },
    { TEXT("ftc"), TEXT("ftc.gov") },
    { TEXT("cdc"), TEXT("cdc.gov") },
    { TEXT("fda"), TEXT("fda.gov") },
    { TEXT("dmv"), TEXT("dmv.org") },
    { TEXT("medicare"), TEXT("medicare.gov") },
    { TEXT("medicaid"), TEXT("medicaid.gov") },

    // 영국
    { TEXT("gov.uk"), TEXT("gov.uk") },
    { TEXT("hmrc"), TEXT("gov.uk") },
    { TEXT("dvla"), TEXT("gov.uk") },
    { TEXT("nhs"), TEXT("nhs.uk") },
    { TEXT("homeoffice"), TEXT("gov.uk") },

    // 캐나다
    { TEXT("canada.ca"), TEXT("canada.ca") },
    { TEXT("cra"), TEXT("canada.ca") },
    { TEXT("servicecanada"), TEXT("canada.ca") },
    { TEXT("cic"), TEXT("canada.ca") },
    { TEXT("ircc"), TEXT("canada.ca") },

    // 호주
    { TEXT("ato"), TEXT("ato.gov.au") },
    { TEXT("australia.gov"), TEXT("australia.gov.au") },
    { TEXT("mygov"), TEXT("my.gov.au") },
    { TEXT("centrelink"), TEXT("servicesaustralia.gov.au") },
    { TEXT("homeaffairs"), TEXT("homeaffairs.gov.au") },

    // 유럽
    { TEXT("gouv.fr"), TEXT("gouv.fr") },
    { TEXT("impots.gouv"), TEXT("impots.gouv.fr") },
    { TEXT("finanzamt"), TEXT("finanzamt.de") },
    { TEXT("elster"), TEXT("elster.de") },
    { TEXT("belastingdienst"), TEXT("belastingdienst.nl") },
    { TEXT("skatteverket"), TEXT("skatteverket.se") },

    // 아시아
    { TEXT("moj"), TEXT("moj.go.jp") },
    { TEXT("nta"), TEXT("nta.go.jp") },
    { TEXT("ird"), TEXT("ird.gov.hk") },
    { TEXT("iras"), TEXT("iras.gov.sg") },
    { TEXT("singpass"), TEXT("singpass.gov.sg") },

    // 한국 세무/재정
    { TEXT("hometax"), TEXT("hometax.go.kr") },
    { TEXT("wetax"), TEXT("wetax.go.kr") },
    { TEXT("etax"), TEXT("etax.go.kr") },
    { TEXT("nts"), TEXT("nts.go.kr") },
    { TEXT("국세청"), TEXT("nts.go.kr") },
    { TEXT("customs"), TEXT("customs.go.kr") },
    { TEXT("관세청"), TEXT("customs.go.kr") },
    { TEXT("mof"), TEXT("moef.go.kr") },
    { TEXT("기획재정부"), TEXT("moef.go.kr") },

    // 한국 사법/치안
    { TEXT("scourt"), TEXT("scourt.go.kr") },
    { TEXT("대법원"), TEXT("scourt.go.kr") },
    { TEXT("court"), TEXT("court.go.kr") },
    { TEXT("법원"), TEXT("court.go.kr") },
    { TEXT("spo"), TEXT("spo.go.kr") },
    { TEXT("검찰청"), TEXT("spo.go.kr") },
    { TEXT("police"), TEXT("police.go.kr") },
    { TEXT("경찰청"), TEXT("police.go.kr") },
    { TEXT("cyberbureau"), TEXT("police.go.kr") },
    { TEXT("moj"), TEXT("moj.go.kr") },
    { TEXT("법무부"), TEXT("moj.go.kr") },
    { TEXT("ccourt"), TEXT("ccourt.go.kr") },
    { TEXT("헌법재판소"), TEXT("ccourt.go.kr") },

    // 한국 행정/민원
    { TEXT("mois"), TEXT("mois.go.kr") },
    { TEXT("행정안전부"), TEXT("mois.go.kr") },
    { TEXT("minwon"), TEXT("minwon.go.kr") },
    { TEXT("민원24"), TEXT("minwon.go.kr") },
    { TEXT("gov"), TEXT("gov.kr") },
    { TEXT("정부24"), TEXT("gov.kr") },
    { TEXT("g4b"), TEXT("g4b.go.kr") },
    { TEXT("epeople"), TEXT("epeople.go.kr") },
    { TEXT("mofa"), TEXT("mofa.go.kr") },
    { TEXT("외교부"), TEXT("mofa.go.kr") },
    { TEXT("mnd"), TEXT("mnd.go.kr") },
    { TEXT("국방부"), TEXT("mnd.go.kr") },
    { TEXT("mma"), TEXT("mma.go.kr") },
    { TEXT("병무청"), TEXT("mma.go.kr") },

    // 한국 복지/고용
    { TEXT("nps"), TEXT("nps.or.kr") },
    { TEXT("국민연금"), TEXT("nps.or.kr") },
    { TEXT("nhis"), TEXT("nhis.or.kr") },
    { TEXT("건강보험"), TEXT("nhis.or.kr") },
    { TEXT("kcomwel"), TEXT("kcomwel.or.kr") },
    { TEXT("근로복지공단"), TEXT("kcomwel.or.kr") },
    { TEXT("moel"), TEXT("moel.go.kr") },
    { TEXT("고용노동부"), TEXT("moel.go.kr") },
    { TEXT("work"), TEXT("work.go.kr") },
    { TEXT("워크넷"), TEXT("work.go.kr") },
    { TEXT("ei"), TEXT("ei.go.kr") },
    { TEXT("고용보험"), TEXT("ei.go.kr") },

    // 한국 우편/교통
    { TEXT("epost"), TEXT("epost.go.kr") },
    { TEXT("우체국"), TEXT("epost.go.kr") },
    { TEXT("koreapost"), TEXT("koreapost.go.kr") },
    { TEXT("우정사업본부"), TEXT("koreapost.go.kr") },
    { TEXT("ex"), TEXT("ex.co.kr") },
    { TEXT("한국도로공사"), TEXT("ex.co.kr") },
    { TEXT("etland"), TEXT("etland.co.kr") },
    { TEXT("highpass"), TEXT("ex.co.kr") },
    { TEXT("molit"), TEXT("molit.go.kr") },
    { TEXT("국토교통부"), TEXT("molit.go.kr") },
    { TEXT("ts2020"), TEXT("ts2020.kr") },
    { TEXT("kotsa"), TEXT("kotsa.or.kr") },
    { TEXT("safedriving"), TEXT("safedriving.or.kr") },

    // 한국 선거/교육
    { TEXT("nec"), TEXT("nec.go.kr") },
    { TEXT("선관위"), TEXT("nec.go.kr") },
    { TEXT("moe"), TEXT("moe.go.kr") },
    { TEXT("교육부"), TEXT("moe.go.kr") },
    { TEXT("neis"), TEXT("neis.go.kr") },
    { TEXT("나이스"), TEXT("neis.go.kr") },

    // 한국 금융/규제
    { TEXT("fsc"), TEXT("fsc.go.kr") },
    { TEXT("금융위원회"), TEXT("fsc.go.kr") },
    { TEXT("fss"), TEXT("fss.or.kr") },
    { TEXT("금융감독원"), TEXT("fss.or.kr") },
    { TEXT("kftc"), TEXT("ftc.go.kr") },
    { TEXT("공정거래위원회"), TEXT("ftc.go.kr") },
    { TEXT("kcc"), TEXT("kcc.go.kr") },
    { TEXT("방송통신위원회"), TEXT("kcc.go.kr") },

    // 한국 기타 공공기관
    { TEXT("kua"), TEXT("kua.go.kr") },
    { TEXT("한국전력"), TEXT("kepco.co.kr") },
    { TEXT("kwater"), TEXT("kwater.or.kr") },
    { TEXT("수자원공사"), TEXT("kwater.or.kr") },
    { TEXT("lh"), TEXT("lh.or.kr") },
    { TEXT("한국토지주택공사"), TEXT("lh.or.kr") },

    // ==================== 국제기구 (International Organizations) ==================== //

    // UN 및 산하기구
    { TEXT("un"), TEXT("un.org") },
    { TEXT("unitednations"), TEXT("un.org") },
    { TEXT("who"), TEXT("who.int") },
    { TEXT("unesco"), TEXT("unesco.org") },
    { TEXT("unicef"), TEXT("unicef.org") },
    { TEXT("unhcr"), TEXT("unhcr.org") },
    { TEXT("wfp"), TEXT("wfp.org") },
    { TEXT("undp"), TEXT("undp.org") },
    { TEXT("unep"), TEXT("unep.org") },
    { TEXT("iaea"), TEXT("iaea.org") },
    { TEXT("ilo"), TEXT("ilo.org") },
    { TEXT("icao"), TEXT("icao.int") },
    { TEXT("imo"), TEXT("imo.org") },
    { TEXT("wmo"), TEXT("wmo.int") },
    { TEXT("unwto"), TEXT("unwto.org") },

    // 국제 경제/금융 기구
    { TEXT("worldbank"), TEXT("worldbank.org") },
    { TEXT("imf"), TEXT("imf.org") },
    { TEXT("wto"), TEXT("wto.org") },
    { TEXT("oecd"), TEXT("oecd.org") },
    { TEXT("bis"), TEXT("bis.org") },
    { TEXT("adb"), TEXT("adb.org") },
    { TEXT("ebrd"), TEXT("ebrd.com") },
    { TEXT("iadb"), TEXT("iadb.org") },
    { TEXT("afdb"), TEXT("afdb.org") },

    // 국제 법률/치안 기구
    { TEXT("interpol"), TEXT("interpol.int") },
    { TEXT("icj"), TEXT("icj-cij.org") },
    { TEXT("icc-cpi"), TEXT("icc-cpi.int") },
    { TEXT("opcw"), TEXT("opcw.org") },

    // 국제 표준/규제 기구
    { TEXT("iso"), TEXT("iso.org") },
    { TEXT("iec"), TEXT("iec.ch") },
    { TEXT("itu"), TEXT("itu.int") },
    { TEXT("icann"), TEXT("icann.org") },
    { TEXT("wipo"), TEXT("wipo.int") },

    // 국제 보건/인도주의
    { TEXT("redcross"), TEXT("icrc.org") },
    { TEXT("ifrc"), TEXT("ifrc.org") },
    { TEXT("msf"), TEXT("msf.org") },
    { TEXT("doctorswithoutborders"), TEXT("msf.org") },

    // 지역 협력체
    { TEXT("eu"), TEXT("europa.eu") },
    { TEXT("europarl"), TEXT("europarl.europa.eu") },
    { TEXT("europol"), TEXT("europol.europa.eu") },
    { TEXT("nato"), TEXT("nato.int") },
    { TEXT("asean"), TEXT("asean.org") },
    { TEXT("apec"), TEXT("apec.org") },
    { TEXT("africanunion"), TEXT("au.int") },
    { TEXT("arab"), TEXT("arableagueonline.org") },

    // ==================== 헬스케어 ==================== //
    { TEXT("cvs"), TEXT("cvs.com") },
    { TEXT("walgreens"), TEXT("walgreens.com") },
    { TEXT("riteaid"), TEXT("riteaid.com") },
    { TEXT("unitedhealth"), TEXT("uhc.com") },
    { TEXT("anthem"), TEXT("anthem.com") },
    { TEXT("aetna"), TEXT("aetna.com") },
    { TEXT("cigna"), TEXT("cigna.com") },
    { TEXT("humana"), TEXT("humana.com") },
    { TEXT("bluecross"), TEXT("bcbs.com") },
    { TEXT("mayoclinic"), TEXT("mayoclinic.org") },
    { TEXT("webmd"), TEXT("webmd.com") },

    // ==================== 자동차 ==================== //
    { TEXT("tesla"), TEXT("tesla.com") },
    { TEXT("ford"), TEXT("ford.com") },
    { TEXT("gm"), TEXT("gm.com") },
    { TEXT("toyota"), TEXT("toyota.com") },
    { TEXT("honda"), TEXT("honda.com") },
    { TEXT("nissan"), TEXT("nissan.com") },
    { TEXT("bmw"), TEXT("bmw.com") },
    { TEXT("mercedes"), TEXT("mercedes-benz.com") },
    { TEXT("volkswagen"), TEXT("volkswagen.com") },
    { TEXT("audi"), TEXT("audi.com") },
    { TEXT("hyundai"), TEXT("hyundai.com") },
    { TEXT("kia"), TEXT("kia.com") },
    { TEXT("genesis"), TEXT("genesis.com") },

    // ==================== 공유 경제 ==================== //
    { TEXT("uber"), TEXT("uber.com") },
    { TEXT("lyft"), TEXT("lyft.com") },
    { TEXT("grab"), TEXT("grab.com") },
    { TEXT("ola"), TEXT("olacabs.com") },
    { TEXT("didi"), TEXT("didiglobal.com") },
    { TEXT("kakaoT"), TEXT("kakaomobility.com") },
    { TEXT("tada"), TEXT("tada.global") },
    { TEXT("socar"), TEXT("socar.kr") },
    { TEXT("greencar"), TEXT("greencar.co.kr") },

    // ==================== 부동산 ==================== //
    { TEXT("zillow"), TEXT("zillow.com") },
    { TEXT("redfin"), TEXT("redfin.com") },
    { TEXT("realtor"), TEXT("realtor.com") },
    { TEXT("trulia"), TEXT("trulia.com") },
    { TEXT("apartmentsdotcom"), TEXT("apartments.com") },

    // 한국 부동산
    { TEXT("zigbang"), TEXT("zigbang.com") },
    { TEXT("dabang"), TEXT("dabang.com") },
    { TEXT("naver"), TEXT("land.naver.com") },
    { TEXT("r114"), TEXT("r114.com") },
    { TEXT("peterpan"), TEXT("peterpanz.com") },

    // ==================== 기타 주요 서비스 ==================== //
    { TEXT("indeed"), TEXT("indeed.com") },
    { TEXT("glassdoor"), TEXT("glassdoor.com") },
    { TEXT("monster"), TEXT("monster.com") },
    { TEXT("careerbuilder"), TEXT("careerbuilder.com") },
    { TEXT("saramin"), TEXT("saramin.co.kr") },
    { TEXT("jobkorea"), TEXT("jobkorea.co.kr") },
    { TEXT("wanted"), TEXT("wanted.co.kr") },

    //  리워드/포인트
    { TEXT("happypoint"), TEXT("happypoint.co.kr") },
    { TEXT("okCashbag"), TEXT("okcashbag.com") },
    { TEXT("lpoint"), TEXT("lpoint.com") },
    { TEXT("shinsegaepoint"), TEXT("shinsegaepoint.com") },

    // 기타
    { TEXT("yelp"), TEXT("yelp.com") },
    { TEXT("tripadvisor"), TEXT("tripadvisor.com") },
    { TEXT("opentable"), TEXT("opentable.com") },
    { TEXT("eventbrite"), TEXT("eventbrite.com") },
    { TEXT("ticketmaster"), TEXT("ticketmaster.com") },
    { TEXT("stubhub"), TEXT("stubhub.com") },
    { TEXT("interpark"), TEXT("interpark.com") },
    { TEXT("yes24"), TEXT("yes24.com") },
    { TEXT("aladin"), TEXT("aladin.co.kr") },
    { TEXT("kyobobook"), TEXT("kyobobook.co.kr") },

    // ==================== 법률 & 사법 서비스 ==================== //

    // 법률 서비스
    { TEXT("legalzoom"), TEXT("legalzoom.com") },
    { TEXT("rocketlawyer"), TEXT("rocketlawyer.com") },
    { TEXT("avvo"), TEXT("avvo.com") },
    { TEXT("nolo"), TEXT("nolo.com") },
    { TEXT("justia"), TEXT("justia.com") },
    { TEXT("findlaw"), TEXT("findlaw.com") },
    { TEXT("martindale"), TEXT("martindale.com") },
    { TEXT("lawyers"), TEXT("lawyers.com") },

    // 공증/인증
    { TEXT("notarize"), TEXT("notarize.com") },
    { TEXT("notarycam"), TEXT("notarycam.com") },
    { TEXT("proof"), TEXT("proof.com") },
    { TEXT("apostille"), TEXT("state.gov") },

    // 법원 시스템
    { TEXT("pacer"), TEXT("pacer.gov") },
    { TEXT("uscourts"), TEXT("uscourts.gov") },
    { TEXT("supremecourt"), TEXT("supremecourt.gov") },

    // 한국 법률
    { TEXT("lawfirm"), TEXT("lawfirm.co.kr") },
    { TEXT("lawissue"), TEXT("lawissue.co.kr") },
    { TEXT("lawtimes"), TEXT("lawtimes.co.kr") },
    { TEXT("koreanlii"), TEXT("law.go.kr") },

    // ==================== IT 지원 & 테크 서비스 ==================== //

    // IT 지원 사칭 (Tech Support Scam 패턴)
    { TEXT("support-microsoft"), TEXT("microsoft.com") },
    { TEXT("microsoft-support"), TEXT("microsoft.com") },
    { TEXT("windows-support"), TEXT("microsoft.com") },
    { TEXT("apple-support"), TEXT("apple.com") },
    { TEXT("support-apple"), TEXT("apple.com") },
    { TEXT("mac-support"), TEXT("apple.com") },
    { TEXT("norton-support"), TEXT("norton.com") },
    { TEXT("mcafee-support"), TEXT("mcafee.com") },
    { TEXT("geeksquad"), TEXT("geeksquad.com") },
    { TEXT("bestbuy-support"), TEXT("bestbuy.com") },
    { TEXT("dell-support"), TEXT("dell.com") },
    { TEXT("hp-support"), TEXT("hp.com") },
    { TEXT("lenovo-support"), TEXT("lenovo.com") },
    { TEXT("samsung-support"), TEXT("samsung.com") },
    { TEXT("asus-support"), TEXT("asus.com") },
    { TEXT("acer-support"), TEXT("acer.com") },

    // 통신사 지원
    { TEXT("verizon-support"), TEXT("verizon.com") },
    { TEXT("att-support"), TEXT("att.com") },
    { TEXT("tmobile-support"), TEXT("t-mobile.com") },
    { TEXT("comcast-support"), TEXT("xfinity.com") },
    { TEXT("xfinity"), TEXT("xfinity.com") },
    { TEXT("spectrum-support"), TEXT("spectrum.com") },
    { TEXT("cox-support"), TEXT("cox.com") },

    // 한국 IT 지원
    { TEXT("lg-support"), TEXT("lge.co.kr") },
    { TEXT("lg전자"), TEXT("lge.co.kr") },
    { TEXT("samsung-service"), TEXT("samsung.com") },
    { TEXT("삼성전자"), TEXT("samsung.com") },
    { TEXT("kt-support"), TEXT("kt.com") },
    { TEXT("skt-support"), TEXT("sktelecom.com") },
    { TEXT("uplus-support"), TEXT("uplus.co.kr") },

    // ====================  AI 서비스 ==================== //

    // OpenAI Ecosystem
    { TEXT("openai"), TEXT("openai.com") },
    { TEXT("chatgpt"), TEXT("openai.com") },
    { TEXT("gpt"), TEXT("openai.com") },
    { TEXT("dalle"), TEXT("openai.com") },
    { TEXT("whisper"), TEXT("openai.com") },

    // Anthropic
    { TEXT("anthropic"), TEXT("anthropic.com") },
    { TEXT("claude"), TEXT("anthropic.com") },

    // Google AI
    { TEXT("gemini"), TEXT("gemini.google.com") },
    { TEXT("bard"), TEXT("bard.google.com") },
    { TEXT("palm"), TEXT("google.com") },

    // Microsoft AI
    { TEXT("copilot"), TEXT("microsoft.com") },
    { TEXT("bing-ai"), TEXT("bing.com") },

    // 기타 AI 서비스
    { TEXT("midjourney"), TEXT("midjourney.com") },
    { TEXT("stability"), TEXT("stability.ai") },
    { TEXT("stablediffusion"), TEXT("stability.ai") },
    { TEXT("huggingface"), TEXT("huggingface.co") },
    { TEXT("replicate"), TEXT("replicate.com") },
    { TEXT("cohere"), TEXT("cohere.com") },
    { TEXT("perplexity"), TEXT("perplexity.ai") },
    { TEXT("character"), TEXT("character.ai") },
    { TEXT("jasper"), TEXT("jasper.ai") },
    { TEXT("writesonic"), TEXT("writesonic.com") },
    { TEXT("copy"), TEXT("copy.ai") },
    { TEXT("runway"), TEXT("runwayml.com") },
    { TEXT("leonardo"), TEXT("leonardo.ai") },
    { TEXT("ideogram"), TEXT("ideogram.ai") },

    // ==================== VPN & 보안 서비스 ==================== //

    { TEXT("nordvpn"), TEXT("nordvpn.com") },
    { TEXT("expressvpn"), TEXT("expressvpn.com") },
    { TEXT("surfshark"), TEXT("surfshark.com") },
    { TEXT("cyberghost"), TEXT("cyberghostvpn.com") },
    { TEXT("privateinternetaccess"), TEXT("privateinternetaccess.com") },
    { TEXT("pia"), TEXT("privateinternetaccess.com") },
    { TEXT("protonvpn"), TEXT("protonvpn.com") },
    { TEXT("protonmail"), TEXT("proton.me") },
    { TEXT("tunnelbear"), TEXT("tunnelbear.com") },
    { TEXT("hotspotshield"), TEXT("hotspotshield.com") },
    { TEXT("windscribe"), TEXT("windscribe.com") },
    { TEXT("ipvanish"), TEXT("ipvanish.com") },
    { TEXT("vyprvpn"), TEXT("vyprvpn.com") },
    { TEXT("purevpn"), TEXT("purevpn.com") },
    { TEXT("mullvad"), TEXT("mullvad.net") },

    // ==================== 추가 암호화폐 서비스 ==================== //

    // DeFi 플랫폼
    { TEXT("uniswap"), TEXT("uniswap.org") },
    { TEXT("pancakeswap"), TEXT("pancakeswap.finance") },
    { TEXT("sushiswap"), TEXT("sushi.com") },
    { TEXT("curve"), TEXT("curve.fi") },
    { TEXT("aave"), TEXT("aave.com") },
    { TEXT("compound"), TEXT("compound.finance") },
    { TEXT("makerdao"), TEXT("makerdao.com") },
    { TEXT("yearn"), TEXT("yearn.finance") },
    { TEXT("balancer"), TEXT("balancer.fi") },
    { TEXT("1inch"), TEXT("1inch.io") },

    // NFT 마켓플레이스
    { TEXT("opensea"), TEXT("opensea.io") },
    { TEXT("rarible"), TEXT("rarible.com") },
    { TEXT("blur"), TEXT("blur.io") },
    { TEXT("foundation"), TEXT("foundation.app") },
    { TEXT("superrare"), TEXT("superrare.com") },
    { TEXT("nifty"), TEXT("niftygateway.com") },
    { TEXT("magiceden"), TEXT("magiceden.io") },
    { TEXT("looksrare"), TEXT("looksrare.org") },

    // 추가 지갑
    { TEXT("phantom"), TEXT("phantom.app") },
    { TEXT("rainbow"), TEXT("rainbow.me") },
    { TEXT("argent"), TEXT("argent.xyz") },
    { TEXT("coinbase-wallet"), TEXT("coinbase.com") },
    { TEXT("walletconnect"), TEXT("walletconnect.com") },
    { TEXT("enjin"), TEXT("enjin.io") },

    // 한국 암호화폐 추가
    { TEXT("dunamu"), TEXT("dunamu.com") },
    { TEXT("upbit-support"), TEXT("upbit.com") },
    { TEXT("bithumb-support"), TEXT("bithumb.com") },

    // ==================== 추가 한국 서비스 ==================== //

    // 배달/모빌리티 확장
    { TEXT("카카오T"), TEXT("kakaomobility.com") },
    { TEXT("배달의민족"), TEXT("baemin.com") },
    { TEXT("요기요"), TEXT("yogiyo.co.kr") },
    { TEXT("쿠팡이츠"), TEXT("coupangeats.com") },
    { TEXT("티맵"), TEXT("tmap.co.kr") },
    { TEXT("tmap"), TEXT("tmap.co.kr") },
    { TEXT("카카오맵"), TEXT("kakao.com") },
    { TEXT("카카오택시"), TEXT("kakaomobility.com") },

    // 포털/콘텐츠
    { TEXT("네이버"), TEXT("naver.com") },
    { TEXT("다음"), TEXT("daum.net") },
    { TEXT("네이트"), TEXT("nate.com") },
    { TEXT("zum"), TEXT("zum.com") },
    { TEXT("카카오스토리"), TEXT("kakao.com") },
    { TEXT("velog"), TEXT("velog.io") },
    { TEXT("브런치"), TEXT("brunch.co.kr") },
    { TEXT("브랜디"), TEXT("brandi.co.kr") },

    // 금융 추가
    { TEXT("토스증권"), TEXT("toss.im") },
    { TEXT("미래에셋증권"), TEXT("miraeasset.com") },
    { TEXT("삼성증권"), TEXT("samsungpop.com") },
    { TEXT("한국투자증권"), TEXT("truefriend.com") },
    { TEXT("kb증권"), TEXT("kbsec.com") },
    { TEXT("nh투자증권"), TEXT("nhqv.com") },
    { TEXT("토스뱅크"), TEXT("tossbank.com") },
    { TEXT("케이뱅크"), TEXT("kbank.com") },
    { TEXT("카카오뱅크"), TEXT("kakaobank.com") },

    // 교육/학습
    { TEXT("classting"), TEXT("classting.com") },
    { TEXT("클래스팅"), TEXT("classting.com") },
    { TEXT("mathpid"), TEXT("mathpid.com") },
    { TEXT("megastudy"), TEXT("megastudy.net") },
    { TEXT("대성마이맥"), TEXT("mimacstudy.com") },
    { TEXT("이투스"), TEXT("etoos.com") },
    { TEXT("에듀윌"), TEXT("eduwill.net") },
    { TEXT("해커스"), TEXT("hackers.com") },

    // 취업/HR
    { TEXT("사람인"), TEXT("saramin.co.kr") },
    { TEXT("잡코리아"), TEXT("jobkorea.co.kr") },
    { TEXT("원티드"), TEXT("wanted.co.kr") },
    { TEXT("링크드인"), TEXT("linkedin.com") },
    { TEXT("인크루트"), TEXT("incruit.com") },
    { TEXT("잡플래닛"), TEXT("jobplanet.co.kr") },
    { TEXT("리멤버"), TEXT("remember.co.kr") },

    // 부동산 추가
    { TEXT("직방"), TEXT("zigbang.com") },
    { TEXT("다방"), TEXT("dabang.com") },
    { TEXT("호갱노노"), TEXT("hogangnono.com") },
    { TEXT("네이버부동산"), TEXT("naver.com") },
    { TEXT("부동산114"), TEXT("r114.com") },

    // 커머스/배송 추가
    { TEXT("무신사"), TEXT("musinsa.com") },
    { TEXT("지그재그"), TEXT("zigzag.kr") },
    { TEXT("에이블리"), TEXT("a-bly.com") },
    { TEXT("29cm"), TEXT("29cm.co.kr") },
    { TEXT("w컨셉"), TEXT("wconcept.co.kr") },
    { TEXT("발란"), TEXT("balaan.co.kr") },
    { TEXT("컬리"), TEXT("kurly.com") },
    { TEXT("쿠팡"), TEXT("coupang.com") },
    { TEXT("네이버쇼핑"), TEXT("naver.com") },
    { TEXT("11번가"), TEXT("11st.co.kr") },
    { TEXT("지마켓"), TEXT("gmarket.co.kr") },
    { TEXT("옥션"), TEXT("auction.co.kr") },

    // 엔터테인먼트
    { TEXT("멜론"), TEXT("melon.com") },
    { TEXT("지니"), TEXT("genie.co.kr") },
    { TEXT("벅스"), TEXT("bugs.co.kr") },
    { TEXT("플로"), TEXT("music-flo.com") },
    { TEXT("바이브"), TEXT("vibe.naver.com") },
    { TEXT("웨이브"), TEXT("wavve.com") },
    { TEXT("티빙"), TEXT("tving.com") },
    { TEXT("왓챠"), TEXT("watcha.com") },

    // 기타 서비스
    { TEXT("당근마켓"), TEXT("daangn.com") },
    { TEXT("중고나라"), TEXT("joonggonara.co.kr") },
    { TEXT("번개장터"), TEXT("bunjang.co.kr") },
    { TEXT("헬로마켓"), TEXT("hellomarket.com") },

    // ==================== 추가 글로벌 서비스 ==================== //

    // 소셜/커뮤니티
    { TEXT("bluesky"), TEXT("bsky.app") },
    { TEXT("mastodon"), TEXT("mastodon.social") },
    { TEXT("substack"), TEXT("substack.com") },
    { TEXT("medium"), TEXT("medium.com") },
    { TEXT("patreon"), TEXT("patreon.com") },
    { TEXT("onlyfans"), TEXT("onlyfans.com") },
    { TEXT("twitch"), TEXT("twitch.tv") },
    { TEXT("kick"), TEXT("kick.com") },
    { TEXT("rumble"), TEXT("rumble.com") },
    { TEXT("vimeo"), TEXT("vimeo.com") },
    { TEXT("dailymotion"), TEXT("dailymotion.com") },

    // 클라우드/개발
    { TEXT("replit"), TEXT("replit.com") },
    { TEXT("codepen"), TEXT("codepen.io") },
    { TEXT("codesandbox"), TEXT("codesandbox.io") },
    { TEXT("stackblitz"), TEXT("stackblitz.com") },
    { TEXT("glitch"), TEXT("glitch.com") },
    { TEXT("railway"), TEXT("railway.app") },
    { TEXT("render"), TEXT("render.com") },
    { TEXT("fly"), TEXT("fly.io") },
    { TEXT("supabase"), TEXT("supabase.com") },
    { TEXT("planetscale"), TEXT("planetscale.com") },
    { TEXT("mongodb"), TEXT("mongodb.com") },
    { TEXT("redis"), TEXT("redis.com") },
    { TEXT("elastic"), TEXT("elastic.co") },
    { TEXT("datadog"), TEXT("datadog.com") },
    { TEXT("newrelic"), TEXT("newrelic.com") },
    { TEXT("sentry"), TEXT("sentry.io") },
    { TEXT("pagerduty"), TEXT("pagerduty.com") },
    { TEXT("statuspage"), TEXT("statuspage.io") },

    // 디자인/크리에이티브 추가
    { TEXT("framer"), TEXT("framer.com") },
    { TEXT("webflow"), TEXT("webflow.com") },
    { TEXT("airtable"), TEXT("airtable.com") },
    { TEXT("notion"), TEXT("notion.so") },
    { TEXT("miro"), TEXT("miro.com") },
    { TEXT("figma"), TEXT("figma.com") },
    { TEXT("affinity"), TEXT("affinity.serif.com") },
    { TEXT("procreate"), TEXT("procreate.com") },

    // 결제/송금 추가
    { TEXT("payoneer"), TEXT("payoneer.com") },
    { TEXT("skrill"), TEXT("skrill.com") },
    { TEXT("neteller"), TEXT("neteller.com") },
    { TEXT("paysafe"), TEXT("paysafe.com") },
    { TEXT("alipay"), TEXT("alipay.com") },
    { TEXT("wechatpay"), TEXT("wechatpay.com") },
    { TEXT("googlepay"), TEXT("pay.google.com") },
    { TEXT("applepay"), TEXT("apple.com") },
    { TEXT("samsungpay"), TEXT("samsung.com") },

    // 쇼핑 추가
    { TEXT("temu"), TEXT("temu.com") },
    { TEXT("shein"), TEXT("shein.com") },
    { TEXT("romwe"), TEXT("romwe.com") },
    { TEXT("zaful"), TEXT("zaful.com") },
    { TEXT("gearbest"), TEXT("gearbest.com") },
    { TEXT("banggood"), TEXT("banggood.com") },
    { TEXT("lightinthebox"), TEXT("lightinthebox.com") },

    // 여행/숙박 추가
    { TEXT("vrbo"), TEXT("vrbo.com") },
    { TEXT("hostelworld"), TEXT("hostelworld.com") },
    { TEXT("hotwire"), TEXT("hotwire.com") },
    { TEXT("orbitz"), TEXT("orbitz.com") },
    { TEXT("lastminute"), TEXT("lastminute.com") },
    { TEXT("rentalcars"), TEXT("rentalcars.com") },
    { TEXT("enterprise"), TEXT("enterprise.com") },
    { TEXT("hertz"), TEXT("hertz.com") },
    { TEXT("avis"), TEXT("avis.com") },
    { TEXT("budget"), TEXT("budget.com") },

    // 건강/피트니스
    { TEXT("strava"), TEXT("strava.com") },
    { TEXT("myfitnesspal"), TEXT("myfitnesspal.com") },
    { TEXT("fitbit"), TEXT("fitbit.com") },
    { TEXT("garmin"), TEXT("garmin.com") },
    { TEXT("peloton"), TEXT("onepeloton.com") },
    { TEXT("noom"), TEXT("noom.com") },
    { TEXT("headspace"), TEXT("headspace.com") },
    { TEXT("calm"), TEXT("calm.com") },

    // 교육
    { TEXT("brilliant"), TEXT("brilliant.org") },
    { TEXT("datacamp"), TEXT("datacamp.com") },
    { TEXT("leetcode"), TEXT("leetcode.com") },
    { TEXT("hackerrank"), TEXT("hackerrank.com") },
    { TEXT("codewars"), TEXT("codewars.com") },
    { TEXT("freecodecamp"), TEXT("freecodecamp.org") },
    { TEXT("sololearn"), TEXT("sololearn.com") },
    { TEXT("treehouse"), TEXT("teamtreehouse.com") },

    // IT 지원 사칭
    { TEXT("amazon-support"), TEXT("amazon.com") },
    { TEXT("ebay-support"), TEXT("ebay.com") },
    { TEXT("paypal-support"), TEXT("paypal.com") },
    { TEXT("google-support"), TEXT("google.com") },
    { TEXT("facebook-support"), TEXT("facebook.com") },
    { TEXT("instagram-support"), TEXT("instagram.com") },
    { TEXT("twitter-support"), TEXT("twitter.com") },
    { TEXT("netflix-support"), TEXT("netflix.com") },
    { TEXT("spotify-support"), TEXT("spotify.com") }
};
