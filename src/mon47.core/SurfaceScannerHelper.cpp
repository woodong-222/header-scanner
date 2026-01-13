#include "pch.h"
#include "SurfaceScannerHelper.h"
#include "Constants.h"
#include "HelperFunc.h"

using namespace Surface;

bool IsDomainMatch(std::tstring strDomain1, std::tstring strDomain2)
{
	const size_t tDomain1Len = strDomain1.length();
	const size_t tDomain2Len = strDomain2.length();
	if (tDomain2Len < tDomain1Len)
	{
		size_t tStartPos = tDomain1Len - tDomain2Len;
		if (strDomain1.substr(tStartPos) == strDomain2 && strDomain1[tStartPos - 1] == '.')
			return true;
	}
	if (tDomain1Len < tDomain2Len)
	{
		size_t tStartPos = tDomain2Len - tDomain1Len;
		if (strDomain1 == strDomain2.substr(tStartPos) && strDomain2[tStartPos - 1] == '.')
			return true;
	}

	return strDomain1 == strDomain2;;
}

bool MatchesOfficialDomain(const std::tstring& strOfficialDomain, const std::tstring& strLowerDomainName, const std::tstring& strLowerFqdn)
{
	if (strOfficialDomain.empty())
		return false;

	if (!IsDomainMatch(strLowerDomainName, strOfficialDomain) &&
		!IsDomainMatch(strLowerFqdn, strOfficialDomain))
		return false;

	return true;
}

/*
* 언어학적 분석: 발음 가능성 검사
* DGA(Domain Generation Algorithm)로 생성된 도메인은 자음 연속, 모음 부족 등의 특징을 가짐
* 정상 도메인은 사람이 기억하기 위해 발음 가능한 구조를 가짐
*/
bool IsPronounceable(const std::tstring& strDomainName)
{
	if (strDomainName.empty()) { return true; }

	std::tstring lower_domain = MakeLower(strDomainName);
	UINT64 vowel_count = 0;
	UINT64 consecutive_consonants = 0;
	UINT64 max_consecutive_consonants = 0;
	UINT64 alpha_count = 0;

	for (UINT64 i = 0; i < lower_domain.length(); ++i)
	{
		TCHAR c = lower_domain[i];

		bool is_vowel = (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');

		if (is_vowel)
		{
			vowel_count++;
			consecutive_consonants = 0;
		}
		else if ('a' < c && c <= 'z')
		{
			alpha_count++;
			consecutive_consonants++;
			if (consecutive_consonants > max_consecutive_consonants)
			{
				max_consecutive_consonants = consecutive_consonants;
			}
		}
		else
		{
			consecutive_consonants = 0; // 하이픈, 숫자 등은 리셋
		}
	}

	// 자음이 5개 이상 연속 (예: xkzqnwrt)
	if (5 <= max_consecutive_consonants)
	{
		return false;
	}

	// 모음 비율 (일반적인 영어 단어 모음 비율 약 30~40%)
	if (6 < alpha_count)
	{
		double ratio = static_cast<double>(vowel_count) / static_cast<double>(alpha_count);
		if (ratio < 0.15) // 모음이 15% 미만
		{
			return false;
		}
	}

	// 자음이 4개 연속된 경우도 의심 (예: qkzj)
	// 길이가 짧을 때
	if (4 <= max_consecutive_consonants && alpha_count <= 8)
	{
		return false;
	}

	return true;
}

/*
* 구문 문자 밀도 계산 ( 특수문자 밀도 )
*/
double CalculateSyntaxDensity(const std::tstring& value)
{
	if (value.empty()) { return 0.0; }

	UINT64 syntax_char_count = 0;
	UINT64 total_len = value.length();

	for (UINT64 i = 0; i < total_len; ++i)
	{
		TCHAR c = value[i];

		// SQLi 및 XSS에서 자주 보이는 문법
		if (c == '\'' || c == '\"' || c == '<' || c == '>' ||
			c == ';' || c == '(' || c == ')' || c == '-' ||
			c == '=' || c == '|' || c == '&' || c == '`' ||
			c == '{' || c == '}' || c == '[' || c == ']')
		{
			syntax_char_count++;
		}
	}

	return static_cast<double>(syntax_char_count) / static_cast<double>(total_len);
}

// 파라미터 키 이름이 숫자를 암시하는지 판단
bool IsNumericParameterKey(const std::tstring& key)
{
	if (key.empty()) { return false; }

	// 정확히 일치하는 숫자형 파라미터 키워드
	static const std::unordered_set<std::tstring> numeric_keywords =
	{
		TEXT("id"), TEXT("idx"), TEXT("no"), TEXT("num"), TEXT("number"),
		TEXT("count"), TEXT("cnt"), TEXT("limit"), TEXT("offset"),
		TEXT("size"), TEXT("page"), TEXT("p"), TEXT("pg"),
		TEXT("seq"), TEXT("order"), TEXT("sort"),
		TEXT("year"), TEXT("month"), TEXT("day"), TEXT("hour"), TEXT("minute"), TEXT("second"),
		TEXT("quantity"), TEXT("qty"), TEXT("amount"), TEXT("price"), TEXT("cost"),
		TEXT("level"), TEXT("rank"), TEXT("score"), TEXT("rating")
	};

	if (0 < numeric_keywords.count(key))
		return true;

	// 접미사 검사 (_id, _no, _idx, _count 등으로 끝나는 경우)
	if (3 < key.length())
	{
		std::tstring suffix_3 = key.substr(key.length() - 3);
		if (suffix_3 == TEXT("_id") || suffix_3 == TEXT("_no")) { return true; }
	}

	if (4 < key.length())
	{
		std::tstring suffix_4 = key.substr(key.length() - 4);
		if (suffix_4 == TEXT("_idx") || suffix_4 == TEXT("_num")) { return true; }
	}

	if (5 < key.length())
	{
		std::tstring suffix_5 = key.substr(key.length() - 5);
		if (suffix_5 == TEXT("_page")) { return true; }
	}

	if (6 < key.length())
	{
		std::tstring suffix_6 = key.substr(key.length() - 6);
		if (suffix_6 == TEXT("_count") || suffix_6 == TEXT("_limit")) { return true; }
	}

	// 접두사 검사 (id_, no_, num_ 등으로 시작하는 경우)
	if (3 < key.length())
	{
		std::tstring prefix_3 = key.substr(0, 3);
		if (prefix_3 == TEXT("id_") || prefix_3 == TEXT("no_")) { return true; }
	}

	if (4 < key.length())
	{
		std::tstring prefix_4 = key.substr(0, 4);
		if (prefix_4 == TEXT("num_") || prefix_4 == TEXT("idx_")) { return true; }
	}

	return false;
}
/*
* 값이 순수 숫자로만 구성되었는지 확인
*/
bool IsNumericValue(const std::tstring& value)
{
	if (value.empty())
		return true;

	for (UINT64 i = 0; i < value.length(); ++i)
	{
		if (!std::isdigit(static_cast<unsigned char>(value[i])))
			return false;
	}
	return true;
}

// 등록 가능한 도메인 추출
std::tstring GetRegistrableDomain(std::tstring strDomain, std::tstring strSuffix)
{
	if (strDomain.empty())
		return TEXT("");

	// 도메인의 Suffix 추출
	if (strSuffix.empty() || strSuffix == strDomain)
		return TEXT("");

	// 도메인에서 Suffix 부분을 제외하고 남은 부분 확인 (예: domain=my.google.co.kr, suffix=co.kr)
	UINT64 suffix_pos = strDomain.rfind(strSuffix);
	if (suffix_pos == std::tstring::npos || suffix_pos == 0)
		return TEXT("");

	// Suffix 바로 앞의 라벨 하나 더하기
	// 예: "google." + "co.kr"
	std::tstring without_suffix = strDomain.substr(0, suffix_pos - 1); // "my.google"
	UINT64 last_dot_in_remainder = without_suffix.rfind('.');

	// 서브도메인 "my.google" -> "google"
	if (last_dot_in_remainder != std::tstring::npos)
		return without_suffix.substr(last_dot_in_remainder + 1) + TEXT(".") + strSuffix;
	else // 루트도메인 "google" -> "google.co.kr"
		return without_suffix + TEXT(".") + strSuffix;

	return TEXT("");
}

std::tstring UserPageScan(const ST_URL_DATA& UrlData)
{
	std::tstring strPath = MakeLower(UrlData.strPath);
	if (strPath.empty())
		return TEXT("");

	// '~' 패턴 검사 (예: /~username/)
	if (strPath.length() > 0 && strPath[0] == '~')
		return strPath;

	//사용자 디렉터리 패턴 검사
	for (const auto& pattern : g_UserDirectoryList)
	{
		if (strPath.rfind(pattern, 0) == 0)
			return pattern;
	}

	return TEXT("");
}

std::tstring TldScan(const ST_URL_DATA& UrlData)
{
	const std::tstring strDomainName = MakeLower(UrlData.strDomainName);
	if (strDomainName.empty())
		return TEXT("");

	// 신뢰할 수 있는 서비스 도메인은 TLD 기반 탐지에서 제외
	if (g_TrustedTldList.count(strDomainName) > 0)
		return TEXT("");

	const std::tstring strTLD = MakeLower(UrlData.strTLD);
	const std::tstring strTLD2 = MakeLower(UrlData.strTLD2);
	if (strTLD.empty())
		return TEXT("");

	if (g_SuspiciousTldList.count(strTLD) == 0 &&
		g_SuspiciousTldList.count(strTLD2) == 0)
		return TEXT("");

	return strTLD;
}

std::tstring ExecutableFileScan(const ST_URL_DATA& UrlData)
{
	if (UrlData.strPath.empty())
		return TEXT("");

	std::tstring strFileName = ExtractFileName(UrlData.strPath);
	std::tstring strExt = MakeLower(ExtractFileExt(strFileName));
	if (0 == g_ExcutableList.count(strExt) &&
		0 == g_MacroDocList.count(strExt))
		return TEXT("");
	return strFileName;
}

std::tstring ShortUrlScan(const ST_URL_DATA& UrlData)
{
	if (UrlData.strDomainName.empty())
		return TEXT("");

	std::tstring strDomainName = MakeLower(UrlData.strDomainName);
	if (0 == g_ShortUrlList.count(strDomainName))
		return TEXT("");
	return UrlData.strDomainName;
}

std::tstring CdnDomainScan(const ST_URL_DATA& UrlData)
{
	if (UrlData.strHostName.empty())
		return TEXT("");

	const std::tstring strHostName = MakeLower(UrlData.strHostName);
	for (const auto& item : g_CdnList)
	{
		const std::tstring& suffix = item.first;
		const std::tstring& provider = item.second;

		// 호스트 길이 체크
		if (strHostName.size() < suffix.length())
			continue;

		// 접미사 비교
		UINT64 compare_pos = strHostName.size() - suffix.length();
		const std::tstring tail = strHostName.substr(compare_pos);
		if (tail == suffix)
			return provider;
	}

	return TEXT("");
}

double DgaScan(const ST_URL_DATA& UrlData)
{
	if (UrlData.strDomainName.empty())
		return 0;

	// 서브도메인 Hex Density 검사
	UINT64 dot_pos = 0;
	UINT64 prev_pos = 0;
	const std::tstring strDomainName = MakeLower(UrlData.strDomainName);

	while ((dot_pos = strDomainName.find('.', prev_pos)) != std::tstring::npos)
	{
		std::tstring label = strDomainName.substr(prev_pos, dot_pos - prev_pos);

		if (6 <= label.length())
		{
			double hex_density = CalculateHexDensity(label);

			// 전체가 16진수 문자로만 구성(1.0)되거나, 매우 높은 비율(0.9 이상)이면 기계 생성 의심
			if (0.9 <= hex_density)
			{
				// 리스트 없이도 기계적으로 생성된 식별자 탐지
				return 9.0; // Hex Density 기반 탐지 표시
			}
		}

		prev_pos = dot_pos + 1;
	}

	// 마지막 라벨 검사
	if (prev_pos < strDomainName.length())
	{
		std::tstring label = strDomainName.substr(prev_pos);
		if (6 <= label.length())
		{
			double hex_density = CalculateHexDensity(label);
			if (0.9 <= hex_density)
			{
				return 9.0;
			}
		}
	}

	double entropy = CalculateEntropy(strDomainName);
	bool is_pronounceable = IsPronounceable(strDomainName);

	// 높은 엔트로피 + 발음 불가능 = DGA 도메인
	if (Thresholds::DgaEntropy < entropy && !is_pronounceable)
		return entropy;

	// 엔트로피가 극단적으로 높으면 발음 가능성과 무관하게 의심
	if ((Thresholds::DgaEntropy + 0.5) < entropy)
		return entropy;

	return 0.0;
}

std::tstring OpenRedirectScan(const ST_URL_DATA& UrlData)
{
	return std::tstring();
}

/*
* Code 19: 타이포 스쿼팅 탐지
* 유명 브랜드의 오타 변형 도메인 탐지
*/

// QWERTY 키보드 좌표 구조체
struct __Internal_Keyboard_key_Point { int x, y; };
// 키보드 상의 거리 계산 [ 유클리드 거리 ]
double GetKeyDistance(char a, char b)
{
	if (a == b) return 0.0;

	static const std::map<char, __Internal_Keyboard_key_Point> keyboard_layout =
	{
		{'1', {0, 0}}, {'2', {1, 0}}, {'3', {2, 0}}, {'4', {3, 0}}, {'5', {4, 0}},
		{'6', {5, 0}}, {'7', {6, 0}}, {'8', {7, 0}}, {'9', {8, 0}}, {'0', {9, 0}},
		{'q', {0, 1}}, {'w', {1, 1}}, {'e', {2, 1}}, {'r', {3, 1}}, {'t', {4, 1}},
		{'y', {5, 1}}, {'u', {6, 1}}, {'i', {7, 1}}, {'o', {8, 1}}, {'p', {9, 1}},
		{'a', {0, 2}}, {'s', {1, 2}}, {'d', {2, 2}}, {'f', {3, 2}}, {'g', {4, 2}},
		{'h', {5, 2}}, {'j', {6, 2}}, {'k', {7, 2}}, {'l', {8, 2}},
		{'z', {0, 3}}, {'x', {1, 3}}, {'c', {2, 3}}, {'v', {3, 3}}, {'b', {4, 3}},
		{'n', {5, 3}}, {'m', {6, 3}}
	};

	std::map<char, __Internal_Keyboard_key_Point>::const_iterator it_a = keyboard_layout.find(a);
	std::map<char, __Internal_Keyboard_key_Point>::const_iterator it_b = keyboard_layout.find(b);
	std::map<char, __Internal_Keyboard_key_Point>::const_iterator it_end = keyboard_layout.end();

	if (it_a == keyboard_layout.end() || it_b == keyboard_layout.end()) // 매핑에 없는 경우
	{
		return 7.0;
	}

	int dx = it_a->second.x - it_b->second.x;
	int dy = it_a->second.y - it_b->second.y;

	// 대각선
	return std::sqrt(static_cast<double>(dx) * dx + static_cast<double>(dy) * dy);
}

// [ Damerau-Levenshtein + Weighted Edit Distance ]
// 인접 키 오타일 경우 cost 낮춤
double WeightedKeyboardDistance(const std::tstring& s1, const std::tstring& s2)
{
	UINT64 len1 = s1.size();
	UINT64 len2 = s2.size();

	std::vector<double> previous_previous(len2 + 1);
	std::vector<double> previous(len2 + 1);
	std::vector<double> current(len2 + 1);

	for (UINT64 j = 0; j <= len2; ++j)
	{
		previous[j] = static_cast<double>(j);
	}

	for (UINT64 i = 1; i <= len1; ++i)
	{
		current[0] = static_cast<double>(i);

		for (UINT64 j = 1; j <= len2; ++j)
		{
			double cost;
			if (s1[i - 1] == s2[j - 1])
			{
				cost = 0.0;
			}
			else
			{
				double dist = GetKeyDistance(s1[i - 1], s2[j - 1]);
				if (dist <= 1.5) cost = 0.5;      // 옆
				else if (dist <= 2.5) cost = 0.8; // 대각선
				else cost = 1.0;                  // 멀리
			}

			current[j] = (std::min)({
				previous[j] + 1.0,       // 삭제 (d[i-1][j])
				current[j - 1] + 1.0,    // 삽입 (d[i][j-1])
				previous[j - 1] + cost   // 교체 (d[i-1][j-1])
				});

			// 인접 문자 바뀐 경우
			if (i > 1 && j > 1 && s1[i - 1] == s2[j - 2] && s1[i - 2] == s2[j - 1])
			{
				current[j] = (std::min)(current[j], previous_previous[j - 2] + 0.5);
			}
		}

		// 행 순환: previous_previous ← previous ← current
		std::swap(previous_previous, previous);
		std::swap(previous, current);
	}

	return previous[len2];
}

std::tstring DoubleExtensionScan(const ST_URL_DATA& UrlData)
{
	const std::tstring strFileName = ExtractFileName(UrlData.strPath);
	if (strFileName.empty())
		return TEXT("");

	std::vector<std::tstring> vecToken;
	TokenizeToArray(strFileName, TEXT("."), vecToken);

	const size_t tTokenSize = vecToken.size();
	if (tTokenSize < 3)
		return TEXT("");

	const std::tstring strRealEXT = MakeLower(vecToken[tTokenSize - 1]);
	const std::tstring strFakeEXT = MakeLower(vecToken[tTokenSize - 2]);
	if (g_ExcutableList.find(strRealEXT) == g_ExcutableList.end())
		return TEXT("");

	if (g_DocExt.find(strFakeEXT) == g_DocExt.end())
		return TEXT("");

	return strFileName;
}

/*
* Code 22: Suspicious URL Structure Scan
* 의심스러운 URL 구조 탐지
*/
bool SuspiciousUrlStructureScan(std::tstring strFqdn)
{
	std::vector<std::tstring> vecSubDomainToken;
	TokenizeToArray(strFqdn, TEXT("."), vecSubDomainToken);

	// 과도한 서브도메인 깊이 검사
	if (vecSubDomainToken.size() < Surface::Thresholds::MaxSubdomainDepth)
		return false;

	return true;
}

bool ScanAuthorityAbuse(const ST_URL_DATA& UrlData)
{
	if (UrlData.strUserInfo.find(TEXT(".")) == -1)
		return false;

	std::vector<std::tstring> vecToken;
	TokenizeToArray(UrlData.strUserInfo, TEXT("."), vecToken, false);

	if (vecToken.size() < 2)
		return false;

	if (TEXT("www") == vecToken[0])
		return true;

	for (auto iterBrand : g_BrandList)
	{
		if (vecToken[0] == iterBrand.first)
			return true;
	}

	return false;
}

bool PunycodeHomographScan(const std::tstring& strFqdn)
{
	// 퓨니코드 도메인 탐지
	const bool has_punycode = strFqdn.find(TEXT("xn--")) != -1;

	// 비ASCII 문자가 포함되어 있는지 확인
	bool has_unicode = false;
	for (TCHAR c : strFqdn)
	{
		if (c < 128)
			continue;
		has_unicode = true;
		break;
	}

	// 퓨니코드나 유니코드 문자가 없으면 탐지하지 않음
	if (!has_punycode && !has_unicode)
		return false;

	// 다양한 유니코드 블록이 혼합되어 있는지 확인
	bool has_latin = false;
	bool has_cyrillic = false;
	bool has_greek = false;
	bool has_other_script = false;
	for (TCHAR c : strFqdn)
	{
		// Latin
		if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'))
			has_latin = true;

		// Cyrillic (U+0400 ~ U+04FF)
		else if (0x0400 <= c && c <= 0x04FF)
			has_cyrillic = true;

		// Greek (U+0370 ~ U+03FF)
		else if (0x0370 <= c && c <= 0x03FF)
			has_greek = true;

		// 기타 비ASCII 스크립트
		else if (127 < c)
			has_other_script = true;
	}

	int nMixedUnicodeCount = 0;
	if (has_latin) nMixedUnicodeCount++;
	if (has_cyrillic) nMixedUnicodeCount++;
	if (has_greek) nMixedUnicodeCount++;
	if (has_other_script) nMixedUnicodeCount++;

	// 퓨니코드가 있거나 두 개 이상의 스크립트가 혼합일 경우만 탐지
	if (!has_punycode && 2 <= nMixedUnicodeCount)
		return false;

	return true;
}

bool SensitiveTokenScan(const std::map<std::tstring, std::tstring>& mapParam)
{
	// OAuth 표준 파라미터 목록
	static const std::unordered_set<std::tstring> oauth_safe_params =
	{
		TEXT("client_id"), TEXT("clientid"),
		TEXT("redirect_uri"), TEXT("redirecturi"), TEXT("redirect_url"), TEXT("redirecturl"),
		TEXT("response_type"), TEXT("responsetype"),
		TEXT("scope"), TEXT("state"), TEXT("nonce"),
		TEXT("access_type"), TEXT("prompt"), TEXT("login_hint"), TEXT("display"),
		TEXT("code_challenge"), TEXT("code_challenge_method")
	};

	for (auto iterParam : mapParam)
	{
		const std::tstring& strParamKey = iterParam.first;
		const std::tstring& strParamValue = iterParam.second;

		for (const std::tstring& strSensitiveToken : g_SensitiveTokenList)
		{
			if (0 < oauth_safe_params.count(strSensitiveToken))
				continue;

			if (strSensitiveToken != strParamKey)
				continue;

			if (strParamValue.length() < Surface::Thresholds::MinTokenLength)
				continue;

			double dValueEntropy = CalculateEntropy(strParamValue);
			if (Surface::Thresholds::MinTokenEntropy <= dValueEntropy)
				return true;
		}
	}

	return false;
}

static const std::map<TCHAR, TCHAR> g_VisualTyposquatMap = {
			{'0', 'o'}, {'1', 'l'}, {'3', 'e'}, {'4', 'a'}, {'5', 's'},
			{'6', 'b'}, {'7', 't'}, {'8', 'b'}, {'9', 'g'},
			{'@', 'a'}, {'$', 's'}, {'!', 'i'}, {'z', 's'}
};

std::tstring NormalizeForTyposquatting(std::tstring strToken)
{
	// -_. 문자들 제거
	strToken.erase(std::remove_if(strToken.begin(), strToken.end(),
		[](unsigned char ch) { return ch == '-' || ch == '_' || ch == '.'; }), strToken.end());

	// 시각적으로 유사한 문자들 매핑
	for (TCHAR& ch : strToken)
	{
		auto iter = g_VisualTyposquatMap.find(ch);
		if (iter == g_VisualTyposquatMap.end())
			continue;

		ch = iter->second;
	}
	Replace(strToken, TEXT("rn"), TEXT("m"));
	Replace(strToken, TEXT("vv"), TEXT("w"));
	Replace(strToken, TEXT("cl"), TEXT("d"));

	// 연속 문자 압축 (예: gooogle -> gogle)
	std::tstring strResult;
	strResult.reserve(strToken.length());
	char last_char = '\0';
	for (char c : strToken)
	{
		if (c != last_char)
		{
			strResult += c;
			last_char = c;
		}
	}

	return std::move(strResult);
}

std::tstring MatchTyposquatting(const UrlData& UrlData)
{
	if (UrlData.strDomainName.empty())
		return TEXT("");

	// 공식 도메인 검사 - 먼저 전체 브랜드 리스트를 순회해서 공식 도메인인지 확인
	// 공식 도메인 체크 (모든 브랜드의 공식 도메인과 비교)
	std::tstring strDomainName = MakeLower(UrlData.strDomainName);
	std::tstring strFqdn = MakeLower(UrlData.strFqdn);
	for (auto it = g_BrandList.begin(); it != g_BrandList.end(); ++it)
	{
		const std::tstring& official_domain = it->second;
		if (MatchesOfficialDomain(official_domain, strDomainName, strFqdn))
			return TEXT("");
	}

	std::vector<std::tstring> vecFqdnToken;
	TokenizeToArray(strFqdn, TEXT("."), vecFqdnToken);
	if (6 < vecFqdnToken.size())
		return TEXT("");

	for (std::tstring strFqdnToken : vecFqdnToken)
	{
		if (strFqdnToken.length() < 5)
			continue;

		// 타이포스쿼팅 검사
		const std::tstring strNormalizedToken = NormalizeForTyposquatting(strFqdnToken);
		for (auto it = g_BrandList.begin(); it != g_BrandList.end(); ++it)
		{
			const std::tstring& strBrandKeyword = it->first;
			const std::tstring& strOfficialDomain = it->second;

			// lenght 5의 기준: line 은 너무 짧고.. online을 탐지하는 경향이 있음
			if (strBrandKeyword.length() < 5)
				continue;

			const std::tstring strNormalizedBrand = NormalizeForTyposquatting(strBrandKeyword);
			if (strNormalizedToken.find(strNormalizedBrand) != -1)
				return strFqdnToken;
		}
	}

	return TEXT("");
}

