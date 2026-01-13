#include "pch.h"
#include "Mon47Engine.h"
#include "resource.h"

CSutraSuper* QuerySutraInstance(void)
{
	static CMon47Engine instance;
	return &instance;
}

CMon47Engine::CMon47Engine(void)
{
}

CMon47Engine::~CMon47Engine(void)
{
}

ECODE CMon47Engine::Descript(SUTRA_DESCRIPT& outDesc)
{
	outDesc.nCoordinateX = 30;
	outDesc.nCoordinateY = 20;
	return EC_SUCCESS;
}

ECODE CMon47Engine::OnURLScan(SUTRA_ANALYZE_URL stUrlInfo)
{
	ECODE nRet = EC_SUCCESS;
	try
	{
		for (const SUTRA_URL_INFO& stURLInfo: stUrlInfo.Urls)
		{
			CHeaderScanner scanner;
			scanner.Scan(stURLInfo.strURL);
		}
	}
	catch (std::exception& e)
	{
		Log_Error("%s", e.what());
		return nRet;
	}

	return EC_SUCCESS;
}
