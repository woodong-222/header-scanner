#include "pch.h"
#include "Scanner.h"

CScanner::CScanner(void)
{
}

CScanner::~CScanner(void)
{
}

ECODE CScanner::Scan(std::tstring strURL)
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
