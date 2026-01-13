#include "pch.h"
#include "HeaderScanner.h"
#include "HeaderScannerHelper.h"

CHeaderScanner::CHeaderScanner(void)
{
}

CHeaderScanner::~CHeaderScanner(void)
{
}

ECODE CHeaderScanner::Scan(std::tstring strURL)
{
	ECODE nRet = EC_SUCCESS;

	std::map<std::tstring, std::tstring> mapDetectParam;
	mapDetectParam[TEXT("url")] = strURL;

	try
	{
	}
	catch (const std::exception& e)
	{
		Log_Error("%s", e.what());
		return nRet;
	}

	return EC_SUCCESS;
}
