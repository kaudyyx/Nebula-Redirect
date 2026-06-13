#ifndef PCH_H
#define PCH_H

#undef UNICODE
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <array>
#include <psapi.h>
#include <string_view>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <type_traits>
#include <algorithm>

// Bring commonly used std symbols into global scope explicitly to avoid
// `using namespace std;` which causes name conflicts (for example with
// Windows SDK typedefs like `byte`).
using std::string;
using std::wstring;
using std::array;
using std::function;
using std::copy_n;
using std::vector;
using std::out_of_range;
using std::is_same_v;
typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;
typedef int64_t int64;
typedef int32_t int32;
typedef int16_t int16;
typedef int8_t int8;

enum EActivationMethod
{
    CommandLine,
    F6,
    Both
};

template <size_t _Sz>
struct ConstexprString
{
    char _St[_Sz];

public:
    consteval ConstexprString( const char( &_Ps )[_Sz] )
    {
        std::copy_n( _Ps, _Sz, _St );
    }

    operator const char* ( )
    {
        return _St;
    }

    constexpr std::string_view StringView( ) const
    {
        return _St;
    }

    constexpr int PatternCount( ) const
    {
        int c = 0;
        for ( int i = 0; i < _Sz; i++ )
        {
            if ( _St[i] == ' ' ) c++;
        }
        return c + 1; // last i think
    }
};

template <typename _Ft>
struct ConstexprFunc
{
    _Ft _Fn;

public:
    consteval ConstexprFunc( _Ft _Pf )
    {
        _Fn = _Pf;
    }

    constexpr _Ft Get( ) const
    {
        return _Fn;
    }
};

template <size_t _Sz>
struct ConstexprArray
{
    uint8_t _Ar[_Sz];
public:
    consteval ConstexprArray( std::array<uint8_t, _Sz> _Pa )
    {
        std::copy_n( _Pa.data( ), _Sz, _Ar );
    }

    constexpr void* Get( ) const
    {
        return (void*) _Ar;
    }
};

namespace Plooshfinder
{
    #include "../plooshfinder/include/plooshfinder.h"
}

template <ConstexprString _St, ConstexprFunc _Cb, ConstexprArray _Ma, ConstexprArray _Mk>
class ConstexprPatch
{
public:
    constexpr Plooshfinder::pf_patch_t Create( )
    {
        return pf_construct_patch( (void*) _Ma.Get( ), (void*) _Mk.Get( ), _St.PatternCount( ), _Cb.Get( ) );
    }
};

namespace Plooshfinder
{
    #include "../plooshfinder/include/plooshfinder_sig.h"
    #include "../plooshfinder/include/formats/pe.h"
};
using namespace Plooshfinder;

namespace Starfall
{
    namespace Types
    {
        enum StarfallURLSet
        {
            Default, // default, private server
            Hybrid, // redirect profile, version, and content pages to private server, otherwise use official
            Dev, // redirect profile & content pages to private server, otherwise use official
            All, // redirect every single request to private server
        };
        enum UEGame
        {
            Generic,
            Fortnite
        };
    }
    using namespace Types;
}
using namespace Starfall;
template <typename T = void>
std::remove_pointer_t<T>* FollowRelative(void* base, int offset) {
    auto addr = (uint8_t*)(__int64(base) + offset + 4) + *(int32_t*)(__int64(base) + offset);
    return (std::remove_pointer_t<T>*)addr;
}
#endif
