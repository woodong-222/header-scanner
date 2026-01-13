#pragma once

extern std::map<std::tstring, WORD> g_DefaultPort;
extern const std::unordered_map<std::tstring, std::tstring> g_CdnList;
extern const std::unordered_set<std::tstring> g_ShortUrlList;
extern const std::unordered_set<std::tstring> g_SuspiciousTldList;
extern const std::unordered_set<std::tstring> g_TrustedTldList;
extern const std::unordered_set<std::tstring> g_SuspiciousPathList;
extern const std::unordered_set<std::tstring> g_DocExt;
extern const std::unordered_set<std::tstring> g_ExcutableList;
extern const std::unordered_set<std::tstring> g_MacroDocList;
extern const std::vector<std::tstring> g_WebVulnList;
extern const std::vector<std::tstring> g_UserDirectoryList;
extern const std::unordered_set<std::tstring> g_SensitiveTokenList;
extern const std::unordered_set<std::tstring> g_AbnormalUriList;
extern const std::unordered_set<std::tstring> g_DangerousParameterList;
extern const std::unordered_set<WORD> g_SuspiciousPortList;
extern const std::unordered_map<std::tstring, std::tstring> g_BrandList;

namespace Surface
{
    namespace Limits
    {
        static constexpr UINT64 MaxUrlLength = 256;
        static constexpr UINT64 MaxDecodeDepth = 5;
    }

    namespace Thresholds
    {
        static constexpr double DgaEntropy = 4.0;
        static constexpr UINT64 MinKeywordCount = 3;
        static constexpr UINT64 MinTokenLength = 16;
        static constexpr double MinTokenEntropy = 3.0;
        static constexpr UINT64 MaxSubdomainDepth = 5;
    }

    namespace Scores
    {
        static constexpr UINT64 Severity4 = 20;
        static constexpr UINT64 Severity3 = 10;
        static constexpr UINT64 Severity2 = 5;
        static constexpr UINT64 Default = 2;
    }
}