#include "pch.h"
#include "HelperFunc.h"
#include "Constants.h"

std::tstring JoinStrings(const std::vector<std::tstring>& vecValues, std::tstring strDelimiter, size_t tStartPos)
{
	std::tstring strRet;
	for (size_t i = tStartPos; i < vecValues.size(); i++)
		strRet += vecValues[i] + strDelimiter;
	strRet = TrimRight(strRet, strDelimiter.c_str());
	return std::move(strRet);
}

// Base64 문자열인지 확인
// 빈 경우, 4로 나누어떨어지지 않는 경우, 잘못된 문자 포함, 패딩이 잘못된 경우 false 반환
bool IsBase64(const std::tstring& str)
{
	if (str.empty())
		return false;

	if (str.length() % 4 != 0)
		return false;

	UINT64 padding_pos = std::tstring::npos;
	for (UINT64 i = 0; i < str.length(); ++i)
	{
		TCHAR c = str[i];
		if (isalnum(c) || c == '+' || c == '/' || c == '-' || c == '_')
		{
			if (padding_pos != std::tstring::npos) { return false; }
			continue;
		}

		if (c == '=')
		{
			if (padding_pos == std::tstring::npos)
			{
				padding_pos = i;
			}
			continue;
		}

		return false;
	}

	if (padding_pos != std::tstring::npos)
	{
		if (str.length() - padding_pos > 2)
			return false;
	}

	return true;
}

// ex) mailto:aaa@bbb.com?subject=제목&body=본문입니다.&cc=cc@example.com&bcc=bcc@example.com
ECODE ParseMailTo(std::tstring strUrl, UrlData& outInfo)
{
	std::tstring strUserInfo;
	outInfo.strScheme = Split(strUrl, TEXT(":"), &strUserInfo);

	std::tstring strMailInfo;
	outInfo.strUserInfo = Split(strUserInfo, TEXT("?"), &strMailInfo);

	return EC_SUCCESS;
}

std::tstring DecodeBase64Helper(std::tstring strContext)
{
	const size_t tReqSize = DecodeBase64(strContext);
	if (tReqSize == 0)
		return TEXT("");

	std::vector<BYTE> vecDecoded(tReqSize);
	DecodeBase64(strContext, vecDecoded.data());
	return TCSFromUTF8((LPCSTR)vecDecoded.data(), vecDecoded.size());
}

std::tstring NormalizeURL(ST_URL_DATA* pUrlData)
{
	std::tstring strRet;
	if (!pUrlData->strScheme.empty())
		strRet += pUrlData->strScheme + TEXT("://");

	if (!pUrlData->strUserInfo.empty())
		strRet += pUrlData->strFqdn + TEXT("@");

	if (!pUrlData->strFqdn.empty())
		strRet += pUrlData->strFqdn;

	if (pUrlData->wPort != g_DefaultPort[pUrlData->strScheme])
		strRet += TEXT(":") + StringFrom(pUrlData->wPort);

	if (!pUrlData->strPath.empty())
		strRet += TEXT("/") + pUrlData->strPath;

	if (!pUrlData->strQuery.empty())
		strRet += TEXT("?") + pUrlData->strQuery;

	if (!pUrlData->strFragment.empty())
		strRet += TEXT("#") + pUrlData->strFragment;

	return std::move(strRet);
}

ECODE ParseURL(std::tstring strURL, UrlData& outInfo)
{
	ECODE nRet = EC_SUCCESS;

	try
	{
		// 이스케이프 (%숫자, 0숫자) 제거
		// 관련샘플: C905E41A8BCC21535DED384AFD6AF34C7DD48DB45D6584749F7A12F77D40A3DA
		//           c2ed9eb91d84f5b6114d34be06b6cabd.pdf
		strURL = DecodeUrlEncoding(strURL);

		// 크롬이나 엣지 같은 일부 브라우저는 자동 치환됨
		// 관련샘플: FA7E1EDD021F78564B3E6FFD5F13D7AF1FE69A1891CC492BA84CCBD77E7F9E31
		strURL = Replace(strURL, TEXT("\\"), TEXT("/"));
		strURL = Replace(strURL, TEXT(";//"), TEXT("://"));

		const size_t tSchemeDelimiterPos = strURL.find(TEXT("://"));
		if (-1 != tSchemeDelimiterPos)
		{
			// scheme 앞부분만 소문자로 치환
			for (size_t i = 0; i < tSchemeDelimiterPos; i++)
			{
				TCHAR& tChar = strURL[i];
				if ('A' <= tChar && tChar <= 'Z')
					tChar += 'a' - 'A';
			}
			while (strURL.find(TEXT("https:///")) != -1)
				strURL = Replace(strURL, TEXT("https:///"), TEXT("https://"));
			while (strURL.find(TEXT("http:///")) != -1)
				strURL = Replace(strURL, TEXT("http:///"), TEXT("http://"));
		}


		nRet = EC_NO_DATA;
		strURL = Trim(strURL);
		if (strURL.empty())
			throw exception_format(TEXT("URL is EMPTY."));

		size_t tPos = 0;
		const size_t tSchemeSep = strURL.find(TEXT("://"), tPos);
		if (std::tstring::npos != tSchemeSep)
		{
			// ex) https://xxx.xxx.xxx.xxx
			outInfo.strScheme = strURL.substr(tPos, tSchemeSep - tPos);
			outInfo.strScheme = MakeLower(outInfo.strScheme);
			tPos = tSchemeSep + 3;
		}
		else if (TEXT("mailto:") == MakeLower(strURL.substr(0, 7)))
			return ParseMailTo(strURL, outInfo);

		const size_t tHostSep = strURL.find(TEXT("/"), tPos);
		if (std::tstring::npos != tHostSep)
			outInfo.strHost = MakeLower(strURL.substr(tPos, tHostSep - tPos));
		else
			outInfo.strHost = MakeLower(strURL.substr(tPos));
		tPos = tHostSep;

		{
			const size_t tUserInfoSep = outInfo.strHost.find(TEXT("@"));
			if (std::tstring::npos != tUserInfoSep)
			{
				outInfo.strUserInfo = outInfo.strHost.substr(0, tUserInfoSep);
				outInfo.strHost = outInfo.strHost.substr(tUserInfoSep + 1);
			}
		}

		{
			const size_t tPortSep = outInfo.strHost.find(TEXT(":"));
			if (std::tstring::npos != tPortSep)
			{
				outInfo.strPort = outInfo.strHost.substr(tPortSep + 1);
				outInfo.strHost = outInfo.strHost.substr(0, tPortSep);
			}
		}

		outInfo.wPort = outInfo.strPort.empty()
			? g_DefaultPort[outInfo.strScheme]
			: WORDFrom(outInfo.strPort);

		outInfo.strFqdn = outInfo.strHost;
		std::vector<std::tstring> vecHostToken;
		TokenizeToArray(outInfo.strHost, TEXT("."), vecHostToken);

		nRet = EC_INVALID_DATA;
		const size_t tHostTokenCount = vecHostToken.size();
		if (tHostTokenCount)
		{
			outInfo.strHostName = vecHostToken[0];
			outInfo.strDomainName = JoinStrings(vecHostToken, TEXT("."), 1);
			outInfo.strTLD = vecHostToken.back();
			if (2 <= tHostTokenCount)
				outInfo.strTLD2 = vecHostToken[tHostTokenCount - 2] + TEXT(".") + outInfo.strTLD;
		}

		if (std::tstring::npos != tPos && strURL[tPos] == TEXT('/'))
		{
			const size_t tPathSep = strURL.find_first_of(TEXT("?#"), ++tPos);
			if (std::tstring::npos != tPathSep)
				outInfo.strPath = strURL.substr(tPos, tPathSep - tPos);
			else
				outInfo.strPath = strURL.substr(tPos);

			tPos = tPathSep;
			TrimRight(outInfo.strPath, TEXT("/"));
		}

		if (std::tstring::npos != tPos && strURL[tPos] == TEXT('?'))
		{
			const size_t tQuerySep = strURL.find(TEXT("#"), ++tPos);
			if (std::tstring::npos != tQuerySep)
				outInfo.strQuery = strURL.substr(tPos, tQuerySep - tPos);
			else
				outInfo.strQuery = strURL.substr(tPos);
			tPos = tQuerySep;

			std::vector<std::tstring> vecParams;
			TokenizeToArray(outInfo.strQuery, TEXT("&"), vecParams);
			for (std::tstring strParam : vecParams)
			{
				std::tstring strKey, strValue;
				strKey = Split(strParam, TEXT("="), &strValue);
				if (IsBase64(strValue))
					strValue = DecodeBase64Helper(strValue);
				outInfo.mapQueryParam[strKey] = strValue;
			}
		}

		if (std::tstring::npos != tPos && strURL[tPos] == TEXT('#'))
			outInfo.strFragment = strURL.substr(++tPos);

		outInfo.strNormalizedURL = NormalizeURL(&outInfo);
	}
	catch (const std::exception& e)
	{
		Log_Error("%s", e.what());
		return nRet;
	}
	return EC_SUCCESS;
}

//16진수 문자 밀도 계산	
double CalculateHexDensity(const std::tstring& label)
{
	if (label.empty()) { return 0.0; }

	UINT64 hex_count = 0;
	UINT64 total_len = label.length();

	for (UINT64 i = 0; i < total_len; ++i)
	{
		if (std::isxdigit(static_cast<unsigned char>(label[i])))
		{
			hex_count++;
		}
	}

	return static_cast<double>(hex_count) / static_cast<double>(total_len);
}

double CalculateEntropy(const std::tstring& str)
{
	if (str.empty()) { return 0.0; }

	std::array<int, 256> counts = { 0 };

	for (TCHAR c : str)
	{
		if (c < 256)
			counts[c]++;
	}

	double entropy = 0.0;
	const double len = static_cast<double>(str.length());

	for (int count : counts)
	{
		if (count > 0)
		{
			double probability = count / len;
			entropy -= probability * log2(probability);
		}
	}

	return entropy;
}

void Evaluate(std::map<std::tstring, std::tstring>& mapDetectParam)
{
	if (mapDetectParam.find(TEXT("typosquatting")) != mapDetectParam.end())
		SutraLog()->AddEvent(7, TEXT("URLHijacking"), std::move(mapDetectParam));
	else if (mapDetectParam.size() == 1)
		SutraLog()->AddEvent(0, TEXT("CleanURL"), std::move(mapDetectParam));
	else
		SutraLog()->AddEvent(4, TEXT("SuspiciousURL"), std::move(mapDetectParam));
}
