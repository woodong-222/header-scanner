#pragma once

class CMon47Engine : public CSutraSuper, public IURLScanner
{
public:
	CMon47Engine(void);
	~CMon47Engine(void);

	ECODE Descript(SUTRA_DESCRIPT& outDesc);
	ECODE OnURLScan(SUTRA_ANALYZE_URL stUrlInfo);
};

