// =============================================================================
//  hwid.cpp  —  HWID production-ready
//  Hash : SHA-256 via Windows CNG (bcrypt.lib) — sem dependência externa
//  Algoritmo: HWIDv1|BIOS=...|BASEBOARD=...|SYS=...|CPU=...|DISK=...|NET=...
//
//  Separação clara:
//    1. Coleta   (funções Collect*)
//    2. Normalização (Normalize)
//    3. Validação    (IsGarbage / ValidateSource)
//    4. Composição   (BuildStringBase)
//    5. Hash         (SHA256Hex)
// =============================================================================

#include "pch.h"
#include "hwid.h"

#include <Windows.h>
#include <bcrypt.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <winioctl.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <set>
#include <map>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

// =============================================================================
//  ESTADO INTERNO
// =============================================================================

static bool g_debugMode = false;

void HWID::SetDebugMode( bool enabled )
{
    g_debugMode = enabled;
}

static void DebugLog( const std::string& msg )
{
    if ( !g_debugMode ) return;
    OutputDebugStringA( ( "[HWID] " + msg + "\n" ).c_str( ) );
}

// =============================================================================
//  SHA-256  via Windows CNG  (bcrypt.lib — nativo no Windows 7+)
// =============================================================================

static std::string SHA256Hex( const std::string& input )
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    // STATUS_SUCCESS == 0, evita incluir <ntstatus.h> que conflita com <windows.h>
    if ( BCryptOpenAlgorithmProvider( &hAlg, BCRYPT_SHA256_ALGORITHM,
         nullptr, 0 ) != 0 )
        return "SHA256_ERR";

    DWORD hashObjSize = 0, dataSize = 0;
    BCryptGetProperty( hAlg, BCRYPT_OBJECT_LENGTH,
                       (PUCHAR) &hashObjSize, sizeof( DWORD ), &dataSize, 0 );

    std::vector<BYTE> hashObj( hashObjSize );
    std::vector<BYTE> digest( 32 ); // SHA-256 = 32 bytes

    if ( BCryptCreateHash( hAlg, &hHash, hashObj.data( ), hashObjSize,
         nullptr, 0, 0 ) != 0 )
    {
        BCryptCloseAlgorithmProvider( hAlg, 0 );
        return "SHA256_ERR";
    }

    BCryptHashData( hHash,
                    reinterpret_cast<PUCHAR>( const_cast<char*>( input.data( ) ) ),
                    static_cast<ULONG>( input.size( ) ), 0 );
    BCryptFinishHash( hHash, digest.data( ), 32, 0 );

    BCryptDestroyHash( hHash );
    BCryptCloseAlgorithmProvider( hAlg, 0 );

    std::ostringstream oss;
    for ( BYTE b : digest )
        oss << std::hex << std::uppercase << std::setw( 2 ) << std::setfill( '0' ) << (int) b;
    return oss.str( ); // 64 chars hex uppercase
}

// =============================================================================
//  NORMALIZAÇÃO
// =============================================================================

static std::string Normalize( const std::string& raw )
{
    std::string s = raw;

    // Remove nulos e caracteres de controle
    s.erase( std::remove_if( s.begin( ), s.end( ),
             [ ] ( unsigned char c )
    {
        return c == '\0' || c < 0x20;
    } ), s.end( ) );

    // Trim espaços
    auto ltrim = s.find_first_not_of( " \t\r\n" );
    auto rtrim = s.find_last_not_of( " \t\r\n" );
    if ( ltrim == std::string::npos ) return "";
    s = s.substr( ltrim, rtrim - ltrim + 1 );

    // Uppercase
    std::transform( s.begin( ), s.end( ), s.begin( ), ::toupper );

    // Colapsa espaços múltiplos em um
    std::string out;
    bool prevSpace = false;
    for ( char c : s )
    {
        if ( c == ' ' )
        {
            if ( !prevSpace ) out += c;
            prevSpace = true;
        }
        else
        {
            out += c;
            prevSpace = false;
        }
    }

    return out;
}

// =============================================================================
//  VALIDAÇÃO — lista de strings inúteis conhecidas
// =============================================================================

static const std::vector<std::string> GARBAGE_VALUES = {
    "", "N/A", "NA", "NONE", "NULL", "0", "00", "000",
    "UNKNOWN", "UNKNOW",
    "TO BE FILLED BY O.E.M.",
    "TO BE FILLED BY OEM",
    "DEFAULT STRING",
    "DEFAULT",
    "SYSTEM SERIAL NUMBER",
    "CHASSIS SERIAL NUMBER",
    "BASE BOARD SERIAL NUMBER",
    "BOARD SERIAL NUMBER",
    "0X00000000",
    "00000000",
    "FFFFFFFF",
    "NOT APPLICABLE",
    "NOT SPECIFIED",
    "INVALID",
    "EMPTY",
    "NO ASSET TAG",
    "ASSET TAG",
    "SERIAL NUMBER",
    "FILL BY OEM",
    "123456789",
    "XXXXXXXX",
    "12345678901234567890",
    "ABCDEFGH",
    "OEM",
    "NONE1",
    "SKU",
    "SYSTEM PRODUCT NAME",
};

static bool IsGarbage( const std::string& normalized )
{
    if ( normalized.empty( ) ) return true;
    if ( normalized.size( ) < 2 ) return true;

    for ( auto& g : GARBAGE_VALUES )
        if ( normalized == g ) return true;

    // String só de zeros ou só de um mesmo char
    bool allSame = std::all_of( normalized.begin( ), normalized.end( ),
                                [&] ( char c )
    {
        return c == normalized[0];
    } );
    if ( allSame && normalized.size( ) >= 4 ) return true;

    return false;
}

// Cria um Source e executa normalização + validação
static HWID::Source MakeSource( const std::string& category,
                                const std::string& key,
                                const std::string& raw,
                                int score )
{
    HWID::Source s;
    s.category = category;
    s.key = key;
    s.raw = raw;
    s.score = score;
    s.normalized = Normalize( raw );
    s.accepted = !IsGarbage( s.normalized );

    if ( !s.accepted )
    {
        s.rejectReason = s.normalized.empty( )
            ? "empty after normalization"
            : "garbage/placeholder value: [" + s.normalized + "]";
    }

    DebugLog( s.category + "." + s.key
              + " raw=[" + s.raw + "]"
              + " norm=[" + s.normalized + "]"
              + ( s.accepted ? " ACCEPTED score=" + std::to_string( s.score )
              : " REJECTED: " + s.rejectReason ) );

    return s;
}

// =============================================================================
//  LEITURA DO REGISTRO
// =============================================================================

static std::string RegReadStr( HKEY root, const char* subkey, const char* value )
{
    HKEY hKey = nullptr;
    if ( RegOpenKeyExA( root, subkey, 0, KEY_READ, &hKey ) != ERROR_SUCCESS )
        return "";

    char buf[512] = {};
    DWORD sz = sizeof( buf );
    DWORD type = 0;
    LSTATUS st = RegQueryValueExA( hKey, value, nullptr, &type,
                                   reinterpret_cast<LPBYTE>( buf ), &sz );
    RegCloseKey( hKey );
    return ( st == ERROR_SUCCESS ) ? std::string( buf, sz > 0 ? sz - 1 : 0 ) : "";
}

// =============================================================================
//  COLETA — BIOS  (score 3 = alta confiabilidade)
// =============================================================================

static void CollectBIOS( std::vector<HWID::Source>& out )
{
    const char* k = "HARDWARE\\DESCRIPTION\\System\\BIOS";

    out.push_back( MakeSource( "BIOS", "Vendor", RegReadStr( HKEY_LOCAL_MACHINE, k, "BIOSVendor" ), 2 ) );
    out.push_back( MakeSource( "BIOS", "Version", RegReadStr( HKEY_LOCAL_MACHINE, k, "BIOSVersion" ), 3 ) );
    out.push_back( MakeSource( "BIOS", "Date", RegReadStr( HKEY_LOCAL_MACHINE, k, "BIOSReleaseDate" ), 2 ) );
}

// =============================================================================
//  COLETA — BASEBOARD  (score 3)
// =============================================================================

static void CollectBaseBoard( std::vector<HWID::Source>& out )
{
    const char* k = "HARDWARE\\DESCRIPTION\\System\\BIOS";

    out.push_back( MakeSource( "BASEBOARD", "Manufacturer",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "BaseBoardManufacturer" ), 2 ) );
    out.push_back( MakeSource( "BASEBOARD", "Product",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "BaseBoardProduct" ), 3 ) );
    out.push_back( MakeSource( "BASEBOARD", "Version",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "BaseBoardVersion" ), 1 ) );
}

// =============================================================================
//  COLETA — SYSTEM (manufacturer + product + family + UUID)
// =============================================================================

static void CollectSystem( std::vector<HWID::Source>& out )
{
    const char* k = "HARDWARE\\DESCRIPTION\\System\\BIOS";

    out.push_back( MakeSource( "SYSTEM", "Manufacturer",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "SystemManufacturer" ), 2 ) );
    out.push_back( MakeSource( "SYSTEM", "ProductName",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "SystemProductName" ), 3 ) );
    out.push_back( MakeSource( "SYSTEM", "Family",
                   RegReadStr( HKEY_LOCAL_MACHINE, k, "SystemFamily" ), 1 ) );
}

// =============================================================================
//  COLETA — CPU  (score 3 para brand string e features; estável entre boots)
// =============================================================================

static void CollectCPU( std::vector<HWID::Source>& out )
{
    // Vendor ID
    int info[4] = {};
    __cpuid( info, 0 );
    char vendor[13] = {};
    *reinterpret_cast<int*>( vendor ) = info[1];
    *reinterpret_cast<int*>( vendor + 4 ) = info[3];
    *reinterpret_cast<int*>( vendor + 8 ) = info[2];
    out.push_back( MakeSource( "CPU", "VendorID", std::string( vendor, 12 ), 2 ) );

    // Processor signature (family/model/stepping — estável no mesmo hw)
    __cpuid( info, 1 );
    std::ostringstream sig;
    sig << std::hex << std::uppercase << std::setw( 8 ) << std::setfill( '0' ) << info[0];
    out.push_back( MakeSource( "CPU", "Signature", sig.str( ), 3 ) );

    // Feature flags EDX — estável no mesmo CPU
    std::ostringstream feat;
    feat << std::hex << std::uppercase << std::setw( 8 ) << std::setfill( '0' ) << (DWORD) info[3];
    out.push_back( MakeSource( "CPU", "FeaturesEDX", feat.str( ), 2 ) );

    // Brand string (48 chars)
    char brand[49] = {};
    for ( int leaf = 0; leaf < 3; leaf++ )
    {
        int b[4] = {};
        __cpuid( b, 0x80000002 + leaf );
        memcpy( brand + leaf * 16, b, 16 );
    }
    out.push_back( MakeSource( "CPU", "BrandString", std::string( brand ), 3 ) );

    // ProcessorRevision via registry (sobrevive a boots)
    out.push_back( MakeSource( "CPU", "Identifier",
                   RegReadStr( HKEY_LOCAL_MACHINE,
                   "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                   "Identifier" ), 2 ) );
    out.push_back( MakeSource( "CPU", "ProcessorNameString",
                   RegReadStr( HKEY_LOCAL_MACHINE,
                   "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                   "ProcessorNameString" ), 2 ) );
}

// =============================================================================
//  COLETA — DISCO (serial físico via IOCTL — score 3)
// =============================================================================

static std::string GetPhysicalSerial( int idx )
{
    char path[32];
    sprintf_s( path, "\\\\.\\PhysicalDrive%d", idx );

    HANDLE h = CreateFileA( path, 0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr );
    if ( h == INVALID_HANDLE_VALUE ) return "";

    STORAGE_PROPERTY_QUERY q = {};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;

    std::vector<BYTE> buf( 1024 );
    DWORD ret = 0;
    BOOL ok = DeviceIoControl( h, IOCTL_STORAGE_QUERY_PROPERTY,
                               &q, sizeof( q ), buf.data( ), (DWORD) buf.size( ), &ret, nullptr );
    CloseHandle( h );
    if ( !ok ) return "";

    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>( buf.data( ) );
    if ( !desc->SerialNumberOffset || desc->SerialNumberOffset >= buf.size( ) ) return "";

    std::string serial( reinterpret_cast<const char*>( buf.data( ) + desc->SerialNumberOffset ) );
    return serial;
}

static void CollectDisk( std::vector<HWID::Source>& out )
{
    // Drive do sistema (onde %SystemDrive% está) via volume serial
    char sysRoot[4] = {};
    char sysRootFull[MAX_PATH] = {};
    if ( GetEnvironmentVariableA( "SystemDrive", sysRoot, sizeof( sysRoot ) ) > 0 )
    {
        sysRoot[2] = '\\'; sysRoot[3] = '\0';
        DWORD volSerial = 0;
        if ( GetVolumeInformationA( sysRoot, nullptr, 0, &volSerial,
             nullptr, nullptr, nullptr, 0 ) )
        {
            std::ostringstream oss;
            oss << std::hex << std::uppercase
                << std::setw( 8 ) << std::setfill( '0' ) << volSerial;
            // volume serial é moderadamente estável (muda com format, não com reboot)
            out.push_back( MakeSource( "DISK", "VolumeSerial_" + std::string( sysRoot, 1 ),
                           oss.str( ), 2 ) );
        }
    }

    // Seriais físicos (drives 0-3, pega o primeiro válido = drive principal)
    for ( int i = 0; i < 4; i++ )
    {
        std::string serial = GetPhysicalSerial( i );
        if ( !serial.empty( ) )
        {
            out.push_back( MakeSource( "DISK", "Physical_" + std::to_string( i ), serial, 3 ) );
        }
    }
}

// =============================================================================
//  COLETA — REDE (opcional, filtro rigoroso de virtuais)
//  Lista de prefixos/substrings de adaptadores virtuais/VPN conhecidos
// =============================================================================

static const std::vector<std::string> VIRTUAL_NIC_PATTERNS = {
    "vmware", "virtualbox", "vbox", "virtual", "tap", "tun",
    "hamachi", "radmin", "tunngle", "wintun", "wireguard",
    "loopback", "pseudo", "miniport", "microsoft wi-fi direct",
    "bluetooth", "wan miniport", "ndis", "npcap", "rawcap",
    "l2tp", "pptp", "sstp", "openvpn", "nordvpn", "expressvpn",
    "surfshark", "mullvad", "proton"
};

static bool IsVirtualAdapter( const std::string& description )
{
    std::string desc = description;
    std::transform( desc.begin( ), desc.end( ), desc.begin( ), ::tolower );
    for ( auto& pattern : VIRTUAL_NIC_PATTERNS )
        if ( desc.find( pattern ) != std::string::npos ) return true;
    return false;
}

static void CollectNetwork( std::vector<HWID::Source>& out )
{
    ULONG bufLen = sizeof( IP_ADAPTER_INFO );
    std::vector<BYTE> buf( bufLen );

    if ( GetAdaptersInfo( reinterpret_cast<PIP_ADAPTER_INFO>( buf.data( ) ), &bufLen )
         == ERROR_BUFFER_OVERFLOW )
        buf.resize( bufLen );

    PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>( buf.data( ) );
    if ( GetAdaptersInfo( adapter, &bufLen ) != NO_ERROR ) return;

    // Coleta MACs válidos → ordena deterministicamente (não depende da ordem do OS)
    std::set<std::string> macs;

    for ( ; adapter; adapter = adapter->Next )
    {
        if ( adapter->AddressLength != 6 ) continue;

        // Descarta all-zeros
        bool allZero = true;
        for ( UINT i = 0; i < 6; i++ )
            if ( adapter->Address[i] )
            {
                allZero = false; break;
            }
        if ( allZero ) continue;

        // Descarta broadcast / multicast (bit 0 do primeiro octeto)
        if ( adapter->Address[0] & 0x01 ) continue;

        // Filtra virtuais pelo description
        if ( IsVirtualAdapter( adapter->Description ) )
        {
            DebugLog( std::string( "NET skip virtual: " ) + adapter->Description );
            continue;
        }

        std::ostringstream oss;
        for ( UINT i = 0; i < 6; i++ )
        {
            if ( i ) oss << '-';
            oss << std::hex << std::uppercase
                << std::setw( 2 ) << std::setfill( '0' )
                << (int) adapter->Address[i];
        }
        macs.insert( oss.str( ) ); // set = ordenação determinística automática
    }

    int idx = 0;
    for ( auto& mac : macs )
    {
        // Score 1: rede é a fonte mais frágil (VPN, troca de NIC etc.)
        out.push_back( MakeSource( "NET", "MAC_" + std::to_string( idx++ ), mac, 1 ) );
    }
}

// =============================================================================
//  COMPOSIÇÃO — monta string-base determinística e versionada
// =============================================================================

static std::string BuildStringBase( const std::vector<HWID::Source>& sources )
{
    // Agrupa por categoria, ordena por key dentro de cada categoria
    // Categorias em ordem fixa para garantir mesmo resultado sempre
    const std::vector<std::string> CATEGORY_ORDER = {
        "BIOS", "BASEBOARD", "SYSTEM", "CPU", "DISK", "NET"
    };

    std::map<std::string, std::vector<std::string>> grouped;
    for ( auto& s : sources )
    {
        if ( !s.accepted ) continue;
        grouped[s.category].push_back( s.key + "=" + s.normalized );
    }

    // Dentro de cada categoria, ordena por key (determinístico)
    for ( auto& [cat, vec] : grouped )
        std::sort( vec.begin( ), vec.end( ) );

    std::ostringstream base;
    base << "HWIDv1";

    for ( auto& cat : CATEGORY_ORDER )
    {
        auto it = grouped.find( cat );
        if ( it == grouped.end( ) || it->second.empty( ) ) continue;

        base << "|" << cat << "=";
        for ( size_t i = 0; i < it->second.size( ); i++ )
        {
            if ( i > 0 ) base << ";";
            base << it->second[i];
        }
    }

    return base.str( );
}

// =============================================================================
//  HASH POR CATEGORIA  (para o map de hashes separados)
// =============================================================================

static std::map<std::string, std::string>
BuildCategoryHashes( const std::vector<HWID::Source>& sources )
{
    std::map<std::string, std::vector<std::string>> grouped;

    for ( auto& s : sources )
    {
        if ( !s.accepted ) continue;
        grouped[s.category].push_back( s.key + "=" + s.normalized );
    }

    std::map<std::string, std::string> result;
    for ( auto& [cat, vec] : grouped )
    {
        std::sort( vec.begin( ), vec.end( ) );
        std::string catStr = cat + "|";
        for ( auto& v : vec ) catStr += v + ";";
        result[cat] = SHA256Hex( catStr );
    }
    return result;
}

// =============================================================================
//  FUNÇÃO PRINCIPAL
// =============================================================================

HWID::CollectResult HWID::Generate( )
{
    CollectResult result;
    result.acceptedCount = 0;
    result.totalScore = 0;
    result.reliable = false;

    auto& src = result.sources;

    DebugLog( "=== HWID::Generate() start ===" );

    // Coleta todas as fontes
    CollectBIOS( src );
    CollectBaseBoard( src );
    CollectSystem( src );
    CollectCPU( src );
    CollectDisk( src );
    CollectNetwork( src );

    // Conta aceitos e score total
    for ( auto& s : src )
    {
        if ( s.accepted )
        {
            result.acceptedCount++;
            result.totalScore += s.score;
        }
    }

    // Confiável se score >= 8 (pelo menos algumas fontes de alta qualidade)
    result.reliable = ( result.totalScore >= 8 );

    DebugLog( "Accepted: " + std::to_string( result.acceptedCount )
              + " | Score: " + std::to_string( result.totalScore )
              + " | Reliable: " + ( result.reliable ? "YES" : "NO" ) );

    // Monta string-base
    result.stringBase = BuildStringBase( src );
    DebugLog( "StringBase: " + result.stringBase );

    // SHA-256 final
    result.hwid = SHA256Hex( result.stringBase );
    DebugLog( "HWID: " + result.hwid );

    // Hashes por categoria
    result.categoryHashes = BuildCategoryHashes( src );
    for ( auto& [cat, hash] : result.categoryHashes )
        DebugLog( "Hash[" + cat + "] = " + hash );

    DebugLog( "=== HWID::Generate() end ===" );

    return result;
}

// =============================================================================
//  AUTOTESTE — roda N vezes e verifica se o HWID é estável
// =============================================================================

bool HWID::SelfTest( int runs, std::string* outReport )
{
    std::ostringstream report;
    report << "HWID SelfTest (" << runs << " runs)\n";
    report << std::string( 50, '-' ) << "\n";

    std::string first;
    bool stable = true;

    for ( int i = 0; i < runs; i++ )
    {
        auto r = Generate( );
        report << "Run " << ( i + 1 ) << ": " << r.hwid
            << " | Score=" << r.totalScore
            << " | Accepted=" << r.acceptedCount
            << " | Reliable=" << ( r.reliable ? "YES" : "NO" ) << "\n";

        if ( i == 0 )
        {
            first = r.hwid;
        }
        else if ( r.hwid != first )
        {
            stable = false;
            report << "  *** INSTABILITY DETECTED (differs from run 1) ***\n";
        }
    }

    report << std::string( 50, '-' ) << "\n";
    report << "Result: " << ( stable ? "STABLE ✓" : "UNSTABLE ✗" ) << "\n";
    report << "Final HWID: " << first << "\n";

    if ( outReport ) *outReport = report.str( );

    OutputDebugStringA( report.str( ).c_str( ) );

    return stable;
}

// =============================================================================
//  DUMP PARA ARQUIVO — %TEMP%\hwid_dump.txt
// =============================================================================

void HWID::DumpToTemp( const CollectResult& result )
{
    char tempPath[MAX_PATH] = {};
    GetTempPathA( MAX_PATH, tempPath );
    std::string path = std::string( tempPath ) + "hwid_dump.txt";

    std::ofstream f( path, std::ios::out | std::ios::trunc );
    if ( !f.is_open( ) ) return;

    SYSTEMTIME st = {};
    GetLocalTime( &st );
    char ts[64] = {};
    sprintf_s( ts, "%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond );

    f << "================================================================\n";
    f << "  HWID DUMP  |  " << ts << "\n";
    f << "  Hash: SHA-256  |  Format: HWIDv1\n";
    f << "================================================================\n\n";

    // ── Fontes detalhadas ────────────────────────────────────────────────────
    f << "[SOURCES]\n";
    std::string lastCat;
    for ( auto& s : result.sources )
    {
        if ( s.category != lastCat )
        {
            f << "\n  -- " << s.category << " --\n";
            lastCat = s.category;
        }
        f << "  " << std::left << std::setw( 28 ) << ( s.key + ":" )
            << " raw=[" << s.raw << "]\n";
        f << "  " << std::string( 28, ' ' )
            << " norm=[" << s.normalized << "]\n";
        f << "  " << std::string( 28, ' ' )
            << " " << ( s.accepted
                        ? "ACCEPTED (score=" + std::to_string( s.score ) + ")"
                        : "REJECTED — " + s.rejectReason )
            << "\n";
    }

    // ── String-base ──────────────────────────────────────────────────────────
    f << "\n[STRING BASE]\n  " << result.stringBase << "\n";

    // ── Hashes por categoria ─────────────────────────────────────────────────
    f << "\n[CATEGORY HASHES]\n";
    for ( auto& [cat, hash] : result.categoryHashes )
        f << "  " << std::left << std::setw( 12 ) << cat << ": " << hash << "\n";

    // ── HWID final ───────────────────────────────────────────────────────────
    f << "\n[FINAL HWID]\n";
    f << "  Algorithm  : SHA-256\n";
    f << "  Score      : " << result.totalScore
        << " (accepted=" << result.acceptedCount << ")\n";
    f << "  Reliable   : " << ( result.reliable ? "YES" : "NO" ) << "\n";
    f << "  HWID       : " << result.hwid << "\n";
    f << "================================================================\n";

    f.close( );
}